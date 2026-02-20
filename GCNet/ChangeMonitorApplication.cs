using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;

namespace GCNet
{
    internal sealed class ChangeMonitorApplication
    {
        private readonly ConcurrentDictionary<string, BaselineEntry> _baseline = new ConcurrentDictionary<string, BaselineEntry>();

        public int Run(Options options)
        {
            using (var connection = LDAPSearches.InitializeConnection())
            {
                var baseDn = string.IsNullOrWhiteSpace(options.BaseDn) ? GetBaseDn() : options.BaseDn;
                var dnIgnoreFilters = LoadDnIgnoreFilters(options.DnIgnoreListPath);
                Console.WriteLine("Loaded DN ignore filters: " + dnIgnoreFilters.Count + " from " + options.DnIgnoreListPath);

                var trackedAttributes = ParseTrackedAttributes(options.TrackedAttributes);
                if (trackedAttributes.Count > 0)
                {
                    LoadBaseline(connection, baseDn, trackedAttributes);
                }

                MetadataEnricher metadataEnricher = options.EnrichMetadata ? new MetadataEnricher(connection) : null;
                var pipeline = new ChangeProcessingPipeline(_baseline, trackedAttributes, options.EnrichMetadata, metadataEnricher);
                var tokenSource = new CancellationTokenSource();

                using (var writer = new JsonArrayFileWriter(options.OutputPath))
                {
                    var worker = pipeline.StartAsync(tokenSource.Token);
                    var writerTask = Task.Run(() =>
                    {
                        try
                        {
                            foreach (var item in pipeline.Outgoing.GetConsumingEnumerable(tokenSource.Token))
                            {
                                writer.WriteObject(item);
                            }
                        }
                        catch (OperationCanceledException)
                        {
                        }
                    }, tokenSource.Token);

                    StartNotification(baseDn, connection, pipeline.Incoming, dnIgnoreFilters);

                    Console.WriteLine("Monitoring started. Press ENTER to stop.");
                    Console.ReadLine();

                    tokenSource.Cancel();
                    pipeline.Incoming.CompleteAdding();

                    try
                    {
                        Task.WaitAll(new[] { worker, writerTask }, TimeSpan.FromSeconds(5));
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                    }
                }
            }

            return 0;
        }

        private static List<string> ParseTrackedAttributes(string tracked)
        {
            if (string.IsNullOrWhiteSpace(tracked))
            {
                return new List<string>();
            }

            return tracked
                .Split(',')
                .Select(x => x.Trim())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private void StartNotification(
            string baseDn,
            LdapConnection connection,
            BlockingCollection<ChangeEvent> target,
            IReadOnlyCollection<string> dnIgnoreFilters)
        {
            var request = new SearchRequest(
                baseDn,
                "(objectClass=*)",
                System.DirectoryServices.Protocols.SearchScope.Subtree,
                "*",
                "objectGUID");
            request.Controls.Add(new DirectoryNotificationControl { IsCritical = true, ServerSide = true });

            DirectoryControl LDAP_SERVER_LAZY_COMMIT_OID = new DirectoryControl("1.2.840.113556.1.4.619", null, true, true);
            request.Controls.Add(LDAP_SERVER_LAZY_COMMIT_OID);

            DirectoryControl LDAP_SERVER_SHOW_DELETED_OID = new DirectoryControl("1.2.840.113556.1.4.417", null, true, true);
            request.Controls.Add(LDAP_SERVER_SHOW_DELETED_OID);


            DirectoryControl LDAP_SERVER_SHOW_RECYCLED_OID = new DirectoryControl("1.2.840.113556.1.4.2064", null, true, true);
            request.Controls.Add(LDAP_SERVER_SHOW_RECYCLED_OID);

            SearchOptionsControl searchOptions = new SearchOptionsControl(SearchOption.PhantomRoot);
            request.Controls.Add(searchOptions);


            AsyncCallback callback = ar =>
            {
                try
                {
                    var partialResults = connection.GetPartialResults(ar);
                    for (int i = 0; i < partialResults.Count; i++)
                    {
                        var entry = partialResults[i] as SearchResultEntry;
                        if (entry == null)
                        {
                            continue;
                        }

                        var entryDn = (entry.DistinguishedName ?? string.Empty).ToLowerInvariant();
                        if (ShouldIgnoreByDn(entryDn, dnIgnoreFilters))
                        {
                            continue;
                        }

                        var properties = ParseEntry(entry);
                        if (properties == null)
                        {
                            continue;
                        }

                        target.Add(new ChangeEvent
                        {
                            DistinguishedName = entry.DistinguishedName,
                            ObjectGuid = ReadObjectGuid(entry),
                            Properties = properties
                        });
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Callback error: " + ex.Message);
                }
            };

            connection.BeginSendRequest(request, TimeSpan.FromSeconds(60 * 10), PartialResultProcessing.ReturnPartialResultsAndNotifyCallback, callback, connection);
        }

        private static IReadOnlyCollection<string> LoadDnIgnoreFilters(string path)
        {
            var targetPath = string.IsNullOrWhiteSpace(path) ? "dn-ignore-default.txt" : path;

            if (!File.Exists(targetPath))
            {
                File.WriteAllText(targetPath, "# DN filters to ignore, one per line" + Environment.NewLine);
                Console.WriteLine("DN ignore list file was not found and has been created: " + targetPath);
                return Array.Empty<string>();
            }

            return File
                .ReadLines(targetPath)
                .Select(x => x.Trim())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Where(x => !x.StartsWith("#", StringComparison.Ordinal))
                .Select(x => x.ToLowerInvariant())
                .Distinct()
                .ToArray();
        }

        private static bool ShouldIgnoreByDn(string dn, IReadOnlyCollection<string> filters)
        {
            if (string.IsNullOrWhiteSpace(dn) || filters == null || filters.Count == 0)
            {
                return false;
            }

            return filters.Any(filter => dn.Contains(filter));
        }

        private void LoadBaseline(LdapConnection connection, string baseDn, IReadOnlyCollection<string> trackedAttributes)
        {
            var filter = "(|" + string.Join(string.Empty, trackedAttributes.Select(a => "(" + a + "=*)")) + ")";
            var attributes = new List<string> { "objectGUID", "distinguishedName" };
            attributes.AddRange(trackedAttributes);
            var request = new SearchRequest(baseDn, filter, System.DirectoryServices.Protocols.SearchScope.Subtree, attributes.ToArray());
            request.Controls.Add(new PageResultRequestControl(1000));

            while (true)
            {
                var response = (SearchResponse)connection.SendRequest(request);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var guid = ReadObjectGuid(entry);
                    var objectKey = ObjectKeyBuilder.BuildObjectKey(guid, entry.DistinguishedName);

                    var snapshot = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    var properties = ParseEntry(entry);
                    foreach (var attr in trackedAttributes)
                    {
                        snapshot[attr] = CanonicalizeAttribute(properties, attr);
                    }

                    _baseline[objectKey] = new BaselineEntry
                    {
                        DistinguishedName = entry.DistinguishedName,
                        Attributes = snapshot
                    };
                }

                var page = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                if (page == null || page.Cookie == null || page.Cookie.Length == 0)
                {
                    break;
                }

                var pageRequest = request.Controls.OfType<PageResultRequestControl>().First();
                pageRequest.Cookie = page.Cookie;
            }

            Console.WriteLine("Loaded baseline for objects: " + _baseline.Count);
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

        private static Guid? ReadObjectGuid(SearchResultEntry entry)
        {
            if (!entry.Attributes.Contains("objectGUID"))
            {
                return null;
            }

            var bytes = entry.Attributes["objectGUID"][0] as byte[];
            if (bytes == null || bytes.Length == 0)
            {
                return null;
            }

            return new Guid(bytes);
        }

        private static Dictionary<string, object> ParseEntry(SearchResultEntry entry)
        {
            var wrapper = new SearchResultEntryWrapper(entry);
            ILdapUtils ldapUtils = new LdapUtils();
            var processor = new LdapPropertyProcessor(ldapUtils);
            var properties = processor.ParseAllProperties(wrapper);
            var userProperties = processor.ReadUserProperties(wrapper, GetCurrentDomain()).Result;

            foreach (var p in userProperties.Props)
            {
                if (!properties.ContainsKey(p.Key))
                {
                    properties.Add(p.Key, p.Value);
                }
            }

            try
            {
                if (entry.Attributes.Contains("usercertificate"))
                {
                    var certificates = new List<ParsedCertificate>();
                    foreach (var certificateValue in entry.Attributes["usercertificate"])
                    {
                        if (certificateValue is byte[] certificateBytes)
                        {
                            certificates.Add(new ParsedCertificate(certificateBytes));
                        }
                    }

                    properties["usercertificate"] = certificates;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("usercertificate parsing error" + ex.Message);
            }

            try
            {
                if (entry.Attributes.Contains("msexchmailboxsecuritydescriptor"))
                {
                    var rawSecurityDescriptor = new RawSecurityDescriptor((byte[])entry.Attributes["msexchmailboxsecuritydescriptor"][0], 0);
                    properties["msexchmailboxsecuritydescriptor"] = rawSecurityDescriptor.GetSddlForm(AccessControlSections.All);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("msexchmailboxsecuritydescriptor parsing error" + ex.Message);
            }

            properties.Remove("thumbnailphoto");
            properties["distinguishedName"] = entry.DistinguishedName;
            return properties;
        }

        private static string GetCurrentDomain()
        {
            return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
        }

        private static string GetBaseDn()
        {
            using (var rootDse = new DirectoryEntry("LDAP://RootDSE"))
            {
                return rootDse.Properties["defaultNamingContext"].Value.ToString();
            }
        }
    }
}
