using Newtonsoft.Json;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;

using SearchOption = System.DirectoryServices.Protocols.SearchOption;

namespace GCNet
{
    internal sealed class ChangeMonitorApplication
    {
        private readonly ConcurrentDictionary<string, BaselineEntry> _baseline = new ConcurrentDictionary<string, BaselineEntry>();
        private long _notificationCount;

        public int Run(Options options)
        {
            var connection = LDAPSearches.InitializeConnection();
            try
            {
                var baseDn = string.IsNullOrWhiteSpace(options.BaseDn) ? GetBaseDn(connection) : options.BaseDn;
                var dnIgnoreFilters = LoadDnIgnoreFilters(options.DnIgnoreListPath);
                AppConsole.Log("Loaded DN ignore filters: " + dnIgnoreFilters.Count + " from " + options.DnIgnoreListPath);

                var trackedAttributes = ParseTrackedAttributes(options.TrackedAttributes);
                if (trackedAttributes.Count > 0)
                {
                    LoadBaseline(connection, baseDn, trackedAttributes);
                }

                AppConsole.Log("Reopening LDAP connection before starting notifications...");
                connection.Dispose();
                connection = LDAPSearches.InitializeConnection();

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
                    AppConsole.Log("Monitoring starting. Press ENTER to stop.");
                    StartNotification(baseDn, connection, pipeline.Incoming, dnIgnoreFilters, options.UsePhantomRoot);
                    
                    Console.ReadLine();

                    AppConsole.Log("Stopping monitoring and completing pipeline...");
                    tokenSource.Cancel();
                    pipeline.Incoming.CompleteAdding();

                    try
                    {
                        Task.WaitAll(new[] { worker, writerTask }, TimeSpan.FromSeconds(5));
                    }
                    catch (Exception ex)
                    {
                        AppConsole.WriteException(ex, "Error while shutting down worker tasks.");
                    }

                    AppConsole.Log("Shutdown completed.");
                }
            }
            finally
            {
                connection.Dispose();
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
            IReadOnlyCollection<string> dnIgnoreFilters,
            bool usePhantomRoot)
        {
            var request = new SearchRequest(
                baseDn,
                "(objectClass=*)",
                System.DirectoryServices.Protocols.SearchScope.Subtree,
                null
                );
            request.Controls.Add(new DirectoryNotificationControl { IsCritical = true, ServerSide = true });
            request.Controls.Add(new DomainScopeControl());
            /*
            DirectoryControl LDAP_SERVER_LAZY_COMMIT_OID = new DirectoryControl("1.2.840.113556.1.4.619", null, true, true);
            request.Controls.Add(LDAP_SERVER_LAZY_COMMIT_OID);
            */
            DirectoryControl LDAP_SERVER_SHOW_DELETED_OID = new DirectoryControl("1.2.840.113556.1.4.417", null, true, true);
            request.Controls.Add(LDAP_SERVER_SHOW_DELETED_OID);

            DirectoryControl LDAP_SERVER_SHOW_RECYCLED_OID = new DirectoryControl("1.2.840.113556.1.4.2064", null, true, true);
            request.Controls.Add(LDAP_SERVER_SHOW_RECYCLED_OID);

            if (usePhantomRoot)
            {
                SearchOptionsControl searchOptions = new SearchOptionsControl(SearchOption.PhantomRoot);
                request.Controls.Add(searchOptions);
            }

            //AppConsole.LiveCounter("Notifications received total", 0);

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

                        var totalNotifications = Interlocked.Increment(ref _notificationCount);
                        AppConsole.LiveCounter("Notifications received total", totalNotifications);
                    }
                }
                catch (Exception ex)
                {
                    AppConsole.WriteException(ex, "Callback error while processing LDAP notifications." + BuildLdapDiagnostics(ex));
                }
            };

            connection.BeginSendRequest(request, TimeSpan.FromSeconds(60 * 60 * 24), PartialResultProcessing.ReturnPartialResultsAndNotifyCallback, callback, connection);
        }

        private static IReadOnlyCollection<string> LoadDnIgnoreFilters(string path)
        {
            var targetPath = string.IsNullOrWhiteSpace(path) ? Options.DefaultDnIgnoreListPath : path;

            if (!File.Exists(targetPath))
            {
                File.WriteAllText(targetPath, "# DN filters to ignore, one per line" + Environment.NewLine);
                AppConsole.Log("DN ignore list file was not found and has been created: " + targetPath);
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
            /*
            DirectoryControl LDAP_SERVER_LAZY_COMMIT_OID = new DirectoryControl("1.2.840.113556.1.4.619", null, true, true);
            request.Controls.Add(LDAP_SERVER_LAZY_COMMIT_OID);
            */
            request.Controls.Add(new DomainScopeControl());

            var loadedCount = 0;

            AnsiConsole.Progress()
                .AutoClear(false)
                .HideCompleted(true)
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new SpinnerColumn()
                })
                .Start(ctx =>
                {
                    var task = ctx.AddTask("[green]Loading baseline[/]", autoStart: true);
                    task.IsIndeterminate = true;

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

                            loadedCount++;
                            task.Description($"[green]Loading baseline[/] [grey](objects: {loadedCount})[/]");
                        }

                        var page = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                        if (page == null || page.Cookie == null || page.Cookie.Length == 0)
                        {
                            break;
                        }

                        var pageRequest = request.Controls.OfType<PageResultRequestControl>().First();
                        pageRequest.Cookie = page.Cookie;
                    }

                    task.StopTask();
                });

            AppConsole.Log("Loaded baseline for objects: " + _baseline.Count);
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
                AppConsole.WriteException(ex, "usercertificate parsing error");
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
                AppConsole.WriteException(ex, "msexchmailboxsecuritydescriptor parsing error");
            }

            properties.Remove("thumbnailphoto");
            var pwdLastSetKey = properties.Keys.FirstOrDefault(k => string.Equals(k, "pwdLastSet", StringComparison.OrdinalIgnoreCase));
            if (pwdLastSetKey != null)
            {
                var pwdLastSetValue = properties[pwdLastSetKey];
                if ((pwdLastSetValue is long longValue && longValue == -1)
                    || (pwdLastSetValue is int intValue && intValue == -1)
                    || (pwdLastSetValue is string stringValue && stringValue == "-1"))
                {
                    properties[pwdLastSetKey] = null;
                }
            }

            properties["distinguishedName"] = entry.DistinguishedName;
            properties["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return properties;
        }

        private static string GetCurrentDomain()
        {
            return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
        }

        private static string BuildLdapDiagnostics(Exception ex)
        {
            var diagnostics = new StringBuilder();

            var directoryOperationException = ex as DirectoryOperationException ?? ex.InnerException as DirectoryOperationException;
            if (directoryOperationException?.Response != null)
            {
                diagnostics.AppendLine();
                diagnostics.Append("LDAP ResultCode: ").Append(directoryOperationException.Response.ResultCode);
                diagnostics.AppendLine();
                diagnostics.Append("LDAP ErrorMessage: ").Append(directoryOperationException.Response.ErrorMessage ?? "<empty>");

                if (directoryOperationException.Response is SearchResponse searchResponse)
                {
                    diagnostics.AppendLine();
                    diagnostics.Append("LDAP MatchedDN: ").Append(searchResponse.MatchedDN ?? "<empty>");
                }
            }

            var ldapException = ex as LdapException ?? ex.InnerException as LdapException;
            if (ldapException?.ServerErrorMessage != null)
            {
                diagnostics.AppendLine();
                diagnostics.Append("LDAP ServerErrorMessage: ").Append(ldapException.ServerErrorMessage);
            }

            return diagnostics.ToString();
        }

        private static string GetBaseDn(LdapConnection connection)
        {
            var rootDseRequest = new SearchRequest(
                string.Empty,
                "(objectClass=*)",
                System.DirectoryServices.Protocols.SearchScope.Base,
                "defaultNamingContext");

            var rootDseResponse = (SearchResponse)connection.SendRequest(rootDseRequest);
            if (rootDseResponse.Entries.Count != 1 || !rootDseResponse.Entries[0].Attributes.Contains("defaultNamingContext"))
            {
                throw new InvalidOperationException("Unable to read defaultNamingContext from RootDSE via active LDAP connection.");
            }

            return rootDseResponse.Entries[0].Attributes["defaultNamingContext"][0].ToString();
        }
    }
}
