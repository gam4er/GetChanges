using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace GCNet
{
    internal sealed class ChangeProcessingPipeline
    {
        private readonly BlockingCollection<ChangeEvent> _incoming = new BlockingCollection<ChangeEvent>(new ConcurrentQueue<ChangeEvent>());
        private readonly BlockingCollection<Dictionary<string, object>> _outgoing = new BlockingCollection<Dictionary<string, object>>(new ConcurrentQueue<Dictionary<string, object>>());
        private readonly ConcurrentDictionary<string, BaselineEntry> _baseline;
        private readonly HashSet<string> _trackedAttributes;
        private readonly bool _enrichMetadata;
        private readonly MetadataEnricher _metadataEnricher;
        private readonly Func<ChangeEvent, bool> _shouldWrite;

        public ChangeProcessingPipeline(ConcurrentDictionary<string, BaselineEntry> baseline, IEnumerable<string> trackedAttributes, bool enrichMetadata, MetadataEnricher metadataEnricher)
        {
            _baseline = baseline;
            _trackedAttributes = new HashSet<string>(trackedAttributes ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            _enrichMetadata = enrichMetadata;
            _metadataEnricher = metadataEnricher;
            _shouldWrite = _trackedAttributes.Count == 0
                ? (Func<ChangeEvent, bool>)(_ => true)
                : ShouldWriteWhenTrackedAttributesChanged;
        }

        public BlockingCollection<ChangeEvent> Incoming => _incoming;
        public BlockingCollection<Dictionary<string, object>> Outgoing => _outgoing;

        public Task StartAsync(CancellationToken token)
        {
            return Task.Run(() =>
            {
                try
                {
                    foreach (var item in _incoming.GetConsumingEnumerable(token))
                    {
                        if (!_shouldWrite(item))
                        {
                            continue;
                        }

                        var shouldEnrich = _enrichMetadata && _metadataEnricher != null;
                        if (shouldEnrich)
                        {
                            var metadata = _metadataEnricher.LoadMetadata(item.DistinguishedName);
                            item.Properties["msdsReplAttributeMetaData"] = metadata;
                        }

                        _outgoing.Add(item.Properties, token);
                    }
                }
                catch (OperationCanceledException)
                {
                }
                finally
                {
                    _outgoing.CompleteAdding();
                }
            }, token);
        }

        private bool ShouldWriteWhenTrackedAttributesChanged(ChangeEvent changeEvent)
        {
            var snapshot = _trackedAttributes.ToDictionary(
                a => a,
                // We compare canonical JSON strings so multi-valued attributes and objects are diffed by value
                // (stable serialized form), not by runtime type/casing quirks from LDAP parser output.
                a => Canonicalize(changeEvent.Properties, a),
                StringComparer.OrdinalIgnoreCase);

            var objectKey = ObjectKeyBuilder.BuildObjectKey(changeEvent.ObjectGuid, changeEvent.DistinguishedName);
            if (!_baseline.TryGetValue(objectKey, out var existing))
            {
                _baseline[objectKey] = new BaselineEntry { DistinguishedName = changeEvent.DistinguishedName, Attributes = snapshot };
                AddTrackedAttributeDiff(changeEvent.Properties, null, snapshot);
                return true;
            }

            var changed = _trackedAttributes.Any(a => !string.Equals(existing.Attributes.ContainsKey(a) ? existing.Attributes[a] : null, snapshot[a], StringComparison.Ordinal));
            AddTrackedAttributeDiff(changeEvent.Properties, existing.Attributes, snapshot);
            _baseline[objectKey] = new BaselineEntry { DistinguishedName = changeEvent.DistinguishedName, Attributes = snapshot };
            return changed;
        }


        private void AddTrackedAttributeDiff(Dictionary<string, object> properties, Dictionary<string, string> previousSnapshot, Dictionary<string, string> currentSnapshot)
        {
            foreach (var attribute in _trackedAttributes)
            {
                var previousValue = previousSnapshot != null && previousSnapshot.ContainsKey(attribute)
                    ? previousSnapshot[attribute]
                    : "null";
                var currentValue = currentSnapshot[attribute];

                if (string.Equals(previousValue, currentValue, StringComparison.Ordinal))
                {
                    properties[attribute] = DeserializeCanonical(currentValue);
                    continue;
                }

                // <attr>_old/<attr>_new are emitted only on real change so downstream systems can distinguish
                // "attribute present" from "attribute transitioned" without re-diffing full object payloads.
                properties[attribute + "_old"] = DeserializeCanonical(previousValue);
                properties[attribute + "_new"] = DeserializeCanonical(currentValue);
            }
        }

        private static object DeserializeCanonical(string canonical)
        {
            if (string.IsNullOrWhiteSpace(canonical))
            {
                return null;
            }

            var token = JToken.Parse(canonical);
            if (token.Type == JTokenType.Array)
            {
                return token.ToObject<List<object>>();
            }

            if (token.Type == JTokenType.Null)
            {
                return null;
            }

            return token.ToObject<object>();
        }
        private static string Canonicalize(Dictionary<string, object> properties, string attribute)
        {
            if (!properties.TryGetValue(attribute, out var value))
            {
                var actualKey = properties.Keys.FirstOrDefault(k => string.Equals(k, attribute, StringComparison.OrdinalIgnoreCase));
                if (actualKey == null)
                {
                    return "null";
                }

                value = properties[actualKey];
            }

            if (value == null)
            {
                return "null";
            }

            return JsonConvert.SerializeObject(value);
        }

        public void Complete()
        {
            _incoming.CompleteAdding();
            _outgoing.CompleteAdding();
        }
    }
}
