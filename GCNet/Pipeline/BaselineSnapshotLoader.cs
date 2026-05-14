using Newtonsoft.Json;
using Spectre.Console;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace GCNet
{
    internal interface IBaselineSnapshotLoader
    {
        void LoadInitialSnapshot(
            LdapConnection connection,
            string baseDn,
            IReadOnlyCollection<string> trackedAttributes,
            ConcurrentDictionary<string, BaselineEntry> baseline,
            StatusContext statusContext = null);
    }

    internal sealed class BaselineSnapshotLoader : IBaselineSnapshotLoader
    {
        private readonly ILdapEntryParser _entryParser;

        public BaselineSnapshotLoader(ILdapEntryParser entryParser)
        {
            _entryParser = entryParser;
        }

        public void LoadInitialSnapshot(
            LdapConnection connection,
            string baseDn,
            IReadOnlyCollection<string> trackedAttributes,
            ConcurrentDictionary<string, BaselineEntry> baseline,
            StatusContext statusContext = null)
        {
            var trackSecurityDescriptor = trackedAttributes.Contains("nTSecurityDescriptor", StringComparer.OrdinalIgnoreCase);

            // nTSecurityDescriptor is not LDAP-searchable, so it cannot drive a baseline filter.
            // Build the OR filter from the *other* tracked attributes; if SD is the only tracked
            // attribute, fall back to a full-tree scan (every securable object has nTSecurityDescriptor).
            // Memory is bounded by SecurityDescriptorFlagControl(Owner|Group|DACL, no SACL) and the x64 heap.
            var searchableAttributes = trackedAttributes
                .Where(a => !string.Equals(a, "nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase))
                .ToList();

            var filter = searchableAttributes.Count == 0
                ? "(objectClass=*)"
                : "(|" + string.Join(string.Empty, searchableAttributes.Select(a => "(" + a + "=*)")) + ")";

            var attributes = new List<string> { "objectGUID", "distinguishedName" };
            attributes.AddRange(trackedAttributes);
            var request = new SearchRequest(baseDn, filter, SearchScope.Subtree, attributes.ToArray());
            request.Controls.Add(new PageResultRequestControl(1000));
            request.Controls.Add(new DomainScopeControl());

            if (trackSecurityDescriptor)
            {
                // LDAP_SERVER_SD_FLAGS_OID = 1.2.840.113556.1.4.801; mask = Owner | Group | DACL (no SACL).
                request.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl));
            }

            var loadedCount = 0;

            while (true)
            {
                var response = (SearchResponse)connection.SendRequest(request);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var guid = _entryParser.ReadObjectGuid(entry);
                    var objectKey = ObjectKeyBuilder.BuildObjectKey(guid, entry.DistinguishedName);
                    var snapshot = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    /*
                     * долго парсит
                     */
                    var properties = _entryParser.ParseEntryAsync(entry, new System.Threading.CancellationToken()).Result;
                    foreach (var attr in trackedAttributes)
                    {
                        snapshot[attr] = CanonicalizeAttribute(properties, attr);
                    }

                    baseline[objectKey] = new BaselineEntry
                    {
                        DistinguishedName = entry.DistinguishedName,
                        Attributes = snapshot
                    };

                    loadedCount++;
                    statusContext?.Status($"[green]Loading baseline[/] [grey](objects: {loadedCount})[/]");
                }

                var page = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                if (page == null || page.Cookie == null || page.Cookie.Length == 0)
                {
                    break;
                }

                var pageRequest = request.Controls.OfType<PageResultRequestControl>().First();
                pageRequest.Cookie = page.Cookie;
            }

            AppConsole.Log("Loaded baseline for objects: " + baseline.Count);
        }

        private static string CanonicalizeAttribute(Dictionary<string, object> properties, string attribute)
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
    }
}
