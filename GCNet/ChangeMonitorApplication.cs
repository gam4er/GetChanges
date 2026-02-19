using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;

namespace GCNet
{
    internal sealed class ChangeMonitorApplication
    {
        private readonly ConcurrentDictionary<Guid, BaselineEntry> _baseline = new ConcurrentDictionary<Guid, BaselineEntry>();

        public int Run(Options options)
        {
            using (var connection = LDAPSearches.InitializeConnection())
            {
                var baseDn = string.IsNullOrWhiteSpace(options.BaseDn) ? GetBaseDn() : options.BaseDn;
                var filters = FilterLoader.Load(options.FiltersFile);
                if (filters.Count == 0)
                {
                    Console.WriteLine("No LDAP filters were found in the provided file.");
                    return 1;
                }

                var trackedAttributes = ParseTrackedAttributes(options.TrackedAttributes);
                if (trackedAttributes.Count > 0)
                {
                    LoadBaseline(connection, baseDn, trackedAttributes);
                }

                var metadataEnricher = new MetadataEnricher(connection);
                var pipeline = new ChangeProcessingPipeline(_baseline, trackedAttributes, options.EnrichMetadata, metadataEnricher);
                var tokenSource = new CancellationTokenSource();

                using (var writer = new JsonArrayFileWriter(options.OutputPath))
                {
                    var worker = pipeline.StartAsync(tokenSource.Token);
                    var writerTask = Task.Run(() =>
                    {
                        foreach (var item in pipeline.Outgoing.GetConsumingEnumerable(tokenSource.Token))
                        {
                            writer.WriteObject(item);
                        }
                    }, tokenSource.Token);

                    foreach (var filter in filters)
                    {
                        StartNotification(baseDn, filter, connection, pipeline.Incoming);
                    }

                    Console.WriteLine("Monitoring started. Press ENTER to stop.");
                    Console.ReadLine();

                    tokenSource.Cancel();
                    pipeline.Incoming.CompleteAdding();

                    try
                    {
                        Task.WaitAll(new[] { worker, writerTask }, TimeSpan.FromSeconds(5));
                    }
                    catch
                    {
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

        private void StartNotification(string baseDn, string filter, LdapConnection connection, BlockingCollection<ChangeEvent> target)
        {
            var request = new SearchRequest(baseDn, filter, SearchScope.Subtree, null);
            request.Controls.Add(new DirectoryNotificationControl { IsCritical = true, ServerSide = true });
            request.Controls.Add(new SearchOptionsControl(SearchOption.PhantomRoot));

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

            connection.BeginSendRequest(request, TimeSpan.FromMinutes(10), PartialResultProcessing.ReturnPartialResultsAndNotifyCallback, callback, connection);
        }

        private void LoadBaseline(LdapConnection connection, string baseDn, IReadOnlyCollection<string> trackedAttributes)
        {
            var filter = "(|" + string.Join(string.Empty, trackedAttributes.Select(a => "(" + a + "=*)")) + ")";
            var attributes = new List<string> { "objectGUID", "distinguishedName" };
            attributes.AddRange(trackedAttributes);
            var request = new SearchRequest(baseDn, filter, SearchScope.Subtree, attributes.ToArray());
            request.Controls.Add(new PageResultRequestControl(1000));

            while (true)
            {
                var response = (SearchResponse)connection.SendRequest(request);
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var guid = ReadObjectGuid(entry);
                    if (!guid.HasValue)
                    {
                        continue;
                    }

                    var snapshot = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var attr in trackedAttributes)
                    {
                        snapshot[attr] = SerializeAttribute(entry, attr);
                    }

                    _baseline[guid.Value] = new BaselineEntry
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

        private static string SerializeAttribute(SearchResultEntry entry, string attr)
        {
            if (!entry.Attributes.Contains(attr))
            {
                return "null";
            }

            var values = new List<string>();
            foreach (var value in entry.Attributes[attr])
            {
                if (value is byte[] bytes)
                {
                    values.Add(Convert.ToBase64String(bytes));
                }
                else
                {
                    values.Add(value?.ToString());
                }
            }

            return JsonConvert.SerializeObject(values);
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
                    properties["usercertificate"] = new ParsedCertificate((byte[])(entry.Attributes["usercertificate"][0] ?? new byte[] { }));
                }
            }
            catch
            {
            }

            try
            {
                if (entry.Attributes.Contains("msexchmailboxsecuritydescriptor"))
                {
                    var rawSecurityDescriptor = new RawSecurityDescriptor((byte[])entry.Attributes["msexchmailboxsecuritydescriptor"][0], 0);
                    properties["msexchmailboxsecuritydescriptor"] = rawSecurityDescriptor.GetSddlForm(AccessControlSections.All);
                }
            }
            catch
            {
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
