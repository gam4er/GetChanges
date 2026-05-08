using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace GCNet
{
    internal interface IDomainControllerSelector
    {
        string SelectBestDomainController(Options options, out string reason);
    }

    internal sealed class DomainControllerSelector : IDomainControllerSelector
    {
        private static readonly object DcSelectionLock = new object();
        private static readonly List<string> FallbackDomainControllers = new List<string>();
        private static readonly Dictionary<string, CachedProbeResult> ProbeCache = new Dictionary<string, CachedProbeResult>(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ProbeCacheLifetime = TimeSpan.FromMinutes(2);
        private static int FallbackCursor;

        public string SelectBestDomainController(Options options, out string reason)
        {
            var mode = (options.DomainControllerSelectionMode ?? "auto").Trim().ToLowerInvariant();
            if (mode == "manual")
            {
                if (string.IsNullOrWhiteSpace(options.DomainController))
                {
                    throw new ArgumentException("--dc is required when --dc-selection=manual.");
                }

                reason = "manual configuration (--dc)";
                lock (DcSelectionLock)
                {
                    FallbackDomainControllers.Clear();
                    FallbackDomainControllers.Add(options.DomainController.Trim());
                    FallbackCursor = 0;
                }

                return options.DomainController.Trim();
            }

            var discovered = DiscoverDomainControllers();
            if (discovered.Count == 0)
            {
                if (!string.IsNullOrWhiteSpace(options.DomainController))
                {
                    reason = "auto fallback to explicit --dc";
                    return options.DomainController.Trim();
                }

                throw new InvalidOperationException("No domain controllers discovered.");
            }

            var healthy = ProbeDomainControllers(discovered);
            if (healthy.Count == 0)
            {
                if (!string.IsNullOrWhiteSpace(options.DomainController))
                {
                    reason = "no healthy auto-discovered DC, fallback to explicit --dc";
                    return options.DomainController.Trim();
                }

                throw new InvalidOperationException("No healthy domain controllers available.");
            }

            var localSite = GetLocalSiteName();
            var ordered = healthy
                .OrderBy(x => options.PreferSiteLocal
                              && !string.IsNullOrWhiteSpace(localSite)
                              && !string.Equals(x.SiteName, localSite, StringComparison.OrdinalIgnoreCase))
                .ThenBy(x => x.RoundTripTimeMs)
                .ThenBy(x => x.Fqdn, StringComparer.OrdinalIgnoreCase)
                .ToList();

            lock (DcSelectionLock)
            {
                FallbackDomainControllers.Clear();
                FallbackDomainControllers.AddRange(ordered.Select(x => x.Fqdn));

                var selectedIndex = FallbackCursor % FallbackDomainControllers.Count;
                var selected = FallbackDomainControllers[selectedIndex];
                FallbackCursor = (selectedIndex + 1) % FallbackDomainControllers.Count;

                reason = selectedIndex == 0
                    ? "best healthy DC by RTT" + (options.PreferSiteLocal ? " with local-site preference" : string.Empty)
                    : "failover rotation to next healthy DC (index " + selectedIndex + "/" + FallbackDomainControllers.Count + ")";

                AppConsole.Log("dc-fallback-list: " + string.Join(", ", FallbackDomainControllers));
                return selected;
            }
        }

        private static string GetLocalSiteName()
        {
            try
            {
                return ActiveDirectorySite.GetComputerSite().Name;
            }
            catch (Exception ex)
            {
                AppConsole.Log("dc-discovery: unable to determine local AD site. " + ex.Message);
                return null;
            }
        }

        private static List<DomainControllerCandidate> DiscoverDomainControllers()
        {
            var result = new List<DomainControllerCandidate>();
            var domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (string.IsNullOrWhiteSpace(domainName))
            {
                AppConsole.Log("dc-discovery: local machine is not joined to a domain (empty DNS suffix).");
                return result;
            }

            try
            {
                AppConsole.Log("dc-discovery: querying Domain.GetCurrentDomain().DomainControllers");
                var domain = Domain.GetCurrentDomain();
                foreach (DomainController dc in domain.DomainControllers)
                {
                    var name = (dc.Name ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(name))
                    {
                        AppConsole.Log("dc-discovery: skipping controller with empty name.");
                        continue;
                    }

                    AppConsole.Log("dc-discovery: candidate " + name + " (site: " + (dc.SiteName ?? "<unknown>") + ")");
                    result.Add(new DomainControllerCandidate { Fqdn = name, SiteName = dc.SiteName });
                }
            }
            catch (Exception ex)
            {
                AppConsole.Log("dc-discovery: failed via Domain.GetCurrentDomain(), fallback to domain name probe. " + ex.Message);
            }

            if (result.Count == 0)
            {
                AppConsole.Log("dc-discovery: no DCs from Domain.GetCurrentDomain(), fallback candidate is domain DNS name " + domainName);
                result.Add(new DomainControllerCandidate { Fqdn = domainName });
            }

            return result
                .GroupBy(x => x.Fqdn, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .ToList();
        }

        private static List<DomainControllerProbeResult> ProbeDomainControllers(IEnumerable<DomainControllerCandidate> candidates)
        {
            using (var semaphore = new SemaphoreSlim(4))
            {
                var tasks = candidates.Select(candidate => ProbeCandidateAsync(candidate, semaphore)).ToArray();
                Task.WaitAll(tasks);
                return tasks
                    .Select(x => x.Result)
                    .Where(x => x.IsHealthy)
                    .ToList();
            }
        }

        private static async Task<DomainControllerProbeResult> ProbeCandidateAsync(DomainControllerCandidate candidate, SemaphoreSlim semaphore)
        {
            await semaphore.WaitAsync().ConfigureAwait(false);
            try
            {
                AppConsole.Log("dc-probe: checking " + candidate.Fqdn + " (site: " + (candidate.SiteName ?? "<unknown>") + ")");
                var probe = GetCachedOrProbe(candidate.Fqdn, TimeSpan.FromSeconds(3));
                if (probe.IsHealthy)
                {
                    AppConsole.Log("dc-probe-ok: " + candidate.Fqdn + " RTT=" + probe.RoundTripTimeMs + "ms");
                    probe.SiteName = candidate.SiteName;
                }
                else
                {
                    AppConsole.Log("dc-probe-failed: " + candidate.Fqdn + " (" + probe.FailureReason + ")");
                }

                return probe;
            }
            finally
            {
                semaphore.Release();
            }
        }

        private static DomainControllerProbeResult GetCachedOrProbe(string fqdn, TimeSpan timeout)
        {
            lock (ProbeCache)
            {
                if (ProbeCache.TryGetValue(fqdn, out var cached) && cached.ExpiresAtUtc > DateTime.UtcNow)
                {
                    return cached.Result.Clone();
                }
            }

            var probe = ProbeDomainController(fqdn, timeout);
            lock (ProbeCache)
            {
                ProbeCache[fqdn] = new CachedProbeResult
                {
                    ExpiresAtUtc = DateTime.UtcNow.Add(ProbeCacheLifetime),
                    Result = probe.Clone()
                };
            }

            return probe;
        }

        private static DomainControllerProbeResult ProbeDomainController(string fqdn, TimeSpan timeout)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                var identifier = new LdapDirectoryIdentifier(fqdn);
                using (var probeConnection = new LdapConnection(identifier))
                {
                    probeConnection.Timeout = timeout;
                    probeConnection.AuthType = AuthType.Negotiate;
                    probeConnection.SessionOptions.ProtocolVersion = 3;
                    probeConnection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                    probeConnection.Bind();

                    var request = new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "defaultNamingContext");
                    probeConnection.SendRequest(request, timeout);
                }

                stopwatch.Stop();
                return new DomainControllerProbeResult
                {
                    Fqdn = fqdn,
                    IsHealthy = true,
                    RoundTripTimeMs = stopwatch.ElapsedMilliseconds
                };
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                return new DomainControllerProbeResult
                {
                    Fqdn = fqdn,
                    IsHealthy = false,
                    RoundTripTimeMs = long.MaxValue,
                    FailureReason = ex.Message
                };
            }
        }

        private sealed class CachedProbeResult
        {
            public DateTime ExpiresAtUtc { get; set; }
            public DomainControllerProbeResult Result { get; set; }
        }

        private sealed class DomainControllerCandidate
        {
            public string Fqdn { get; set; }
            public string SiteName { get; set; }
        }

        private sealed class DomainControllerProbeResult
        {
            public string Fqdn { get; set; }
            public string SiteName { get; set; }
            public bool IsHealthy { get; set; }
            public long RoundTripTimeMs { get; set; }
            public string FailureReason { get; set; }

            public DomainControllerProbeResult Clone()
            {
                return (DomainControllerProbeResult)MemberwiseClone();
            }
        }
    }
}
