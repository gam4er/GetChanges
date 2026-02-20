using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace GCNet
{
    internal sealed class ChangeMonitorApplication
    {
        private readonly ConcurrentDictionary<string, BaselineEntry> _baseline = new ConcurrentDictionary<string, BaselineEntry>();
        private readonly ILdapConnectionFactory _connectionFactory;
        private readonly ILdapNotificationLoopService _notificationLoopService;
        private readonly IBaselineSnapshotLoader _baselineSnapshotLoader;
        private long _notificationCount;

        public ChangeMonitorApplication()
            : this(
                new LdapConnectionFactory(new DomainControllerSelector()),
                new LdapNotificationLoopService(new LdapEntryParser()),
                new BaselineSnapshotLoader(new LdapEntryParser()))
        {
        }

        internal ChangeMonitorApplication(
            ILdapConnectionFactory connectionFactory,
            ILdapNotificationLoopService notificationLoopService,
            IBaselineSnapshotLoader baselineSnapshotLoader)
        {
            _connectionFactory = connectionFactory;
            _notificationLoopService = notificationLoopService;
            _baselineSnapshotLoader = baselineSnapshotLoader;
        }

        public int Run(Options options)
        {
            ValidateDomainControllerOptions(options);
            Func<LdapConnection> connectionFactory = () => _connectionFactory.CreateBoundConnection(options);

            using (var connection = connectionFactory())
            using (var lifecycle = new MonitoringLifecycleService())
            {
                var baseDn = string.IsNullOrWhiteSpace(options.BaseDn) ? GetBaseDn(connection) : options.BaseDn;
                var dnIgnoreFilters = LoadDnIgnoreFilters(options.DnIgnoreListPath);
                AppConsole.Log("Loaded DN ignore filters: " + dnIgnoreFilters.Count + " from " + options.DnIgnoreListPath);

                var trackedAttributes = ParseTrackedAttributes(options.TrackedAttributes);
                if (trackedAttributes.Count > 0)
                {
                    _baselineSnapshotLoader.LoadInitialSnapshot(connection, baseDn, trackedAttributes, _baseline);
                }

                MetadataEnricher metadataEnricher = options.EnrichMetadata ? new MetadataEnricher(connection) : null;
                var pipeline = new ChangeProcessingPipeline(_baseline, trackedAttributes, options.EnrichMetadata, metadataEnricher);

                using (var writer = new JsonArrayFileWriter(options.OutputPath))
                {
                    var worker = pipeline.StartAsync(lifecycle.Token);
                    var writerTask = StartWriterLoop(pipeline, writer, lifecycle.Token);
                    // Notification loop owns reconnect with capped exponential backoff + jitter,
                    // so the host starts it once and lets the loop self-heal transient LDAP failures.
                    var notificationLoopTask = _notificationLoopService.RunAsync(
                        BuildNotificationLoopContext(baseDn, connectionFactory, pipeline.Incoming, dnIgnoreFilters, options.UsePhantomRoot),
                        lifecycle.Token);

                    lifecycle.WaitForStopSignal();
                    lifecycle.RequestStop();

                    // Shutdown is cooperative first (cancel token), then bounded waits prevent a stuck LDAP callback
                    // from hanging process termination forever.
                    lifecycle.WaitForTask(notificationLoopTask, TimeSpan.FromSeconds(5), "Error while shutting down notification loop.");
                    pipeline.Incoming.CompleteAdding();
                    lifecycle.WaitForTasks(new[] { worker, writerTask }, TimeSpan.FromSeconds(5), "Error while shutting down worker tasks.");
                    AppConsole.Log("Shutdown completed.");
                }
            }

            return 0;
        }

        private NotificationLoopContext BuildNotificationLoopContext(
            string baseDn,
            Func<LdapConnection> connectionFactory,
            BlockingCollection<ChangeEvent> incoming,
            IReadOnlyCollection<string> dnIgnoreFilters,
            bool usePhantomRoot)
        {
            return new NotificationLoopContext
            {
                BaseDn = baseDn,
                ConnectionFactory = connectionFactory,
                Target = incoming,
                DnIgnoreFilters = dnIgnoreFilters,
                UsePhantomRoot = usePhantomRoot,
                OnNotificationReceived = OnNotificationReceived
            };
        }

        private static Task StartWriterLoop(ChangeProcessingPipeline pipeline, JsonArrayFileWriter writer, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                try
                {
                    foreach (var item in pipeline.Outgoing.GetConsumingEnumerable(cancellationToken))
                    {
                        writer.WriteObject(item);
                    }
                }
                catch (OperationCanceledException)
                {
                }
            }, cancellationToken);
        }

        private static void ValidateDomainControllerOptions(Options options)
        {
            var mode = (options.DomainControllerSelectionMode ?? "auto").Trim().ToLowerInvariant();
            if (mode != "auto" && mode != "manual")
            {
                throw new ArgumentException("Invalid --dc-selection value. Supported values: auto, manual.");
            }

            if (mode == "manual" && string.IsNullOrWhiteSpace(options.DomainController))
            {
                throw new ArgumentException("--dc is required when --dc-selection=manual.");
            }

            if (mode == "auto" && !string.IsNullOrWhiteSpace(options.DomainController))
            {
                AppConsole.Log("dc-selection: auto mode with explicit --dc fallback configured.");
            }
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

        private void OnNotificationReceived()
        {
            var totalNotifications = Interlocked.Increment(ref _notificationCount);
            AppConsole.LiveCounter("Notifications received total", totalNotifications);
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
                // DN matching in the callback is case-insensitive substring; normalizing here keeps filter behavior
                // deterministic regardless of how admins format OUs/CNs in the ignore file.
                .Select(x => x.ToLowerInvariant())
                .Distinct()
                .ToArray();
        }

        private static string GetBaseDn(LdapConnection connection)
        {
            var rootDseRequest = new SearchRequest(string.Empty, "(objectClass=*)", SearchScope.Base, "defaultNamingContext");
            var rootDseResponse = (SearchResponse)connection.SendRequest(rootDseRequest);
            if (rootDseResponse.Entries.Count != 1 || !rootDseResponse.Entries[0].Attributes.Contains("defaultNamingContext"))
            {
                throw new InvalidOperationException("Unable to read defaultNamingContext from RootDSE via active LDAP connection.");
            }

            return rootDseResponse.Entries[0].Attributes["defaultNamingContext"][0].ToString();
        }
    }
}
