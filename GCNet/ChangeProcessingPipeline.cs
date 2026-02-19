using Newtonsoft.Json;
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
        private readonly ConcurrentDictionary<Guid, BaselineEntry> _baseline;
        private readonly HashSet<string> _trackedAttributes;
        private readonly bool _enrichMetadata;
        private readonly MetadataEnricher _metadataEnricher;

        public ChangeProcessingPipeline(ConcurrentDictionary<Guid, BaselineEntry> baseline, IEnumerable<string> trackedAttributes, bool enrichMetadata, MetadataEnricher metadataEnricher)
        {
            _baseline = baseline;
            _trackedAttributes = new HashSet<string>(trackedAttributes ?? Enumerable.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            _enrichMetadata = enrichMetadata;
            _metadataEnricher = metadataEnricher;
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
                        var shouldEnrich = _enrichMetadata && ShouldEnrich(item);
                        if (shouldEnrich)
                        {
                            var metadata = _metadataEnricher.LoadMetadata(item.DistinguishedName);
                            item.Properties["msdsReplAttributeMetaData"] = metadata;
                        }

                        _outgoing.Add(item.Properties, token);
                    }
                }
                finally
                {
                    _outgoing.CompleteAdding();
                }
            }, token);
        }

        private bool ShouldEnrich(ChangeEvent changeEvent)
        {
            if (_trackedAttributes.Count == 0)
            {
                return true;
            }

            if (!changeEvent.ObjectGuid.HasValue)
            {
                return true;
            }

            var snapshot = _trackedAttributes.ToDictionary(
                a => a,
                a => Canonicalize(changeEvent.Properties, a),
                StringComparer.OrdinalIgnoreCase);

            var guid = changeEvent.ObjectGuid.Value;
            if (!_baseline.TryGetValue(guid, out var existing))
            {
                _baseline[guid] = new BaselineEntry { DistinguishedName = changeEvent.DistinguishedName, Attributes = snapshot };
                return true;
            }

            var changed = _trackedAttributes.Any(a => !string.Equals(existing.Attributes.ContainsKey(a) ? existing.Attributes[a] : null, snapshot[a], StringComparison.Ordinal));
            _baseline[guid] = new BaselineEntry { DistinguishedName = changeEvent.DistinguishedName, Attributes = snapshot };
            return changed;
        }

        private static string Canonicalize(Dictionary<string, object> properties, string attribute)
        {
            if (!properties.TryGetValue(attribute, out var value) || value == null)
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
