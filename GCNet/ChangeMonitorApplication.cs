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
        private static readonly object BackoffRandomLock = new object();
        private static readonly Random BackoffRandom = new Random();

        public int Run(Options options)
        {
            var connectionFactory = new Func<LdapConnection>(LDAPSearches.CreateBoundConnection);
            var connection = connectionFactory();
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

                    var notificationLoopTask = Task.Run(() => RunNotificationLoop(
                        baseDn,
                        connectionFactory,
                        pipeline.Incoming,
                        dnIgnoreFilters,
                        options.UsePhantomRoot,
                        tokenSource.Token), tokenSource.Token);

                    AppConsole.Log("Monitoring starting. Press ENTER to stop.");

                    Console.ReadLine();

                    AppConsole.Log("Stopping monitoring and completing pipeline...");
                    tokenSource.Cancel();

                    try
                    {
                        notificationLoopTask.Wait(TimeSpan.FromSeconds(5));
                    }
                    catch (Exception ex)
                    {
                        AppConsole.WriteException(ex, "Error while shutting down notification loop.");
                    }

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

        private void RunNotificationLoop(
            string baseDn,
            Func<LdapConnection> connectionFactory,
            BlockingCollection<ChangeEvent> target,
            IReadOnlyCollection<string> dnIgnoreFilters,
            bool usePhantomRoot,
            CancellationToken cancellationToken)
        {
            var attempt = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                LdapConnection sessionConnection = null;
                NotificationSubscription subscription = null;
                var restartSignal = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                try
                {
                    AppConsole.Log("connect: creating LDAP notification session");
                    sessionConnection = connectionFactory();

                    var request = BuildNotificationRequest(baseDn, usePhantomRoot);
                    subscription = new NotificationSubscription(
                        sessionConnection,
                        request,
                        target,
                        dnIgnoreFilters,
                        cancellationToken,
                        OnNotificationReceived,
                        ex =>
                        {
                            AppConsole.WriteException(ex, "callback-fail: recoverable LDAP notification error." + BuildLdapDiagnostics(ex));
                            restartSignal.TrySetResult(true);
                        });

                    AppConsole.Log("subscribe: starting LDAP change notification subscription");
                    subscription.Start();

                    AppConsole.Log("reconnect-success: LDAP notification session is active");
                    attempt = 0;

                    WaitForRestartOrCancellation(restartSignal.Task, cancellationToken);
                }
                catch (Exception ex) when (IsRecoverableNotificationException(ex))
                {
                    AppConsole.WriteException(ex, "callback-fail: recoverable session error while starting/serving notifications." + BuildLdapDiagnostics(ex));
                }
                finally
                {
                    subscription?.Dispose();
                    sessionConnection?.Dispose();
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                attempt++;
                var delay = CalculateReconnectDelay(attempt);
                AppConsole.Log("reconnect-attempt: waiting " + delay + " before creating new LDAP session");
                try
                {
                    Task.Delay(delay, cancellationToken).Wait(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        private void OnNotificationReceived()
        {
            var totalNotifications = Interlocked.Increment(ref _notificationCount);
            AppConsole.LiveCounter("Notifications received total", totalNotifications);
        }

        private sealed class NotificationSubscription : IDisposable
        {
            private readonly LdapConnection _connection;
            private readonly SearchRequest _request;
            private readonly BlockingCollection<ChangeEvent> _target;
            private readonly IReadOnlyCollection<string> _dnIgnoreFilters;
            private readonly CancellationToken _cancellationToken;
            private readonly Action _onNotificationReceived;
            private readonly Action<Exception> _onError;
            private IAsyncResult _asyncResult;
            private int _stopped;

            public NotificationSubscription(
                LdapConnection connection,
                SearchRequest request,
                BlockingCollection<ChangeEvent> target,
                IReadOnlyCollection<string> dnIgnoreFilters,
                CancellationToken cancellationToken,
                Action onNotificationReceived,
                Action<Exception> onError)
            {
                _connection = connection;
                _request = request;
                _target = target;
                _dnIgnoreFilters = dnIgnoreFilters;
                _cancellationToken = cancellationToken;
                _onNotificationReceived = onNotificationReceived;
                _onError = onError;
            }

            public void Start()
            {
                _asyncResult = _connection.BeginSendRequest(
                    _request,
                    TimeSpan.FromDays(1),
                    PartialResultProcessing.ReturnPartialResultsAndNotifyCallback,
                    OnPartialResults,
                    _connection);
            }

            public void Stop()
            {
                if (Interlocked.Exchange(ref _stopped, 1) == 1)
                {
                    return;
                }

                try
                {
                    if (_asyncResult != null)
                    {
                        _connection.Abort(_asyncResult);
                    }
                }
                catch (Exception)
                {
                }
            }

            public void Dispose()
            {
                Stop();
            }

            private void OnPartialResults(IAsyncResult ar)
            {
                if (Volatile.Read(ref _stopped) == 1 || _cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                try
                {
                    var partialResults = _connection.GetPartialResults(ar);
                    for (int i = 0; i < partialResults.Count; i++)
                    {
                        if (_cancellationToken.IsCancellationRequested)
                        {
                            return;
                        }

                        var entry = partialResults[i] as SearchResultEntry;
                        if (entry == null)
                        {
                            continue;
                        }

                        var entryDn = (entry.DistinguishedName ?? string.Empty).ToLowerInvariant();
                        if (ShouldIgnoreByDn(entryDn, _dnIgnoreFilters))
                        {
                            continue;
                        }

                        var properties = ParseEntry(entry);
                        if (properties == null)
                        {
                            continue;
                        }

                        _target.Add(new ChangeEvent
                        {
                            DistinguishedName = entry.DistinguishedName,
                            ObjectGuid = ReadObjectGuid(entry),
                            Properties = properties
                        }, _cancellationToken);

                        _onNotificationReceived();
                    }
                }
                catch (Exception ex)
                {
                    _onError(ex);
                }
            }
        }

        private static SearchRequest BuildNotificationRequest(string baseDn, bool usePhantomRoot)
        {
            var request = new SearchRequest(
                baseDn,
                "(objectClass=*)",
                System.DirectoryServices.Protocols.SearchScope.Subtree,
                null
            );

            request.Controls.Add(new DirectoryNotificationControl { IsCritical = true, ServerSide = true });
            request.Controls.Add(new DomainScopeControl());

            DirectoryControl LDAP_SERVER_SHOW_DELETED_OID = new DirectoryControl("1.2.840.113556.1.4.417", null, true, true);
            request.Controls.Add(LDAP_SERVER_SHOW_DELETED_OID);

            DirectoryControl LDAP_SERVER_SHOW_RECYCLED_OID = new DirectoryControl("1.2.840.113556.1.4.2064", null, true, true);
            request.Controls.Add(LDAP_SERVER_SHOW_RECYCLED_OID);

            if (usePhantomRoot)
            {
                SearchOptionsControl searchOptions = new SearchOptionsControl(SearchOption.PhantomRoot);
                request.Controls.Add(searchOptions);
            }

            return request;
        }

        private static bool IsRecoverableNotificationException(Exception ex)
        {
            return ex is LdapException
                || ex is DirectoryOperationException
                || ex is ObjectDisposedException
                || ex is IOException
                || ex.InnerException is LdapException
                || ex.InnerException is DirectoryOperationException
                || ex.InnerException is IOException;
        }

        private static TimeSpan CalculateReconnectDelay(int attempt)
        {
            var cappedAttempt = Math.Min(attempt, 6);
            var baseDelaySeconds = Math.Pow(2, Math.Max(0, cappedAttempt - 1));
            double jitter;
            lock (BackoffRandomLock)
            {
                jitter = BackoffRandom.NextDouble() * 0.2;
            }
            var delayWithJitter = baseDelaySeconds * (1.0 + jitter);
            return TimeSpan.FromSeconds(Math.Min(60, delayWithJitter));
        }

        private static void WaitForRestartOrCancellation(Task restartTask, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (restartTask.Wait(TimeSpan.FromMilliseconds(250)))
                {
                    return;
                }
            }
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
