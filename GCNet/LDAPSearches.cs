using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net.NetworkInformation;

using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace GCNet
{
    internal interface IDomainControllerSelector
    {
        string SelectBestDomainController(Options options, out string reason);
    }

    internal interface ILdapConnectionFactory
    {
        LdapConnection CreateBoundConnection(Options options);
    }

    internal interface ILdapSchemaHelper
    {
        string GetSchemaNamingContext(LdapConnection ldapConnection);
        Dictionary<string, string> GetAllAttributes(LdapConnection ldapConnection);
    }

    internal sealed class LDAPSearches
    {
        private static readonly IDomainControllerSelector DomainControllerSelector = new DomainControllerSelector();
        private static readonly ILdapConnectionFactory ConnectionFactory = new LdapConnectionFactory(DomainControllerSelector);
        private static readonly ILdapSchemaHelper SchemaHelper = new LdapSchemaHelper();

        public static LdapConnection CreateBoundConnection(Options options)
        {
            return ConnectionFactory.CreateBoundConnection(options);
        }

        public static string GetSchemaNamingContext(LdapConnection ldapConnection)
        {
            return SchemaHelper.GetSchemaNamingContext(ldapConnection);
        }

        public static Dictionary<string, string> GetAllAttributes(LdapConnection ldapConnection)
        {
            return SchemaHelper.GetAllAttributes(ldapConnection);
        }

        public static string GetUserOU()
        {
            var user = UserPrincipal.Current;
            DirectoryEntry deUser = user.GetUnderlyingObject() as DirectoryEntry;
            DirectoryEntry deUserContainer = deUser.Parent;
            return deUserContainer.Properties["distinguishedName"].Value.ToString();
        }

        public static string SelectBestDomainController(Options options, out string reason)
        {
            return DomainControllerSelector.SelectBestDomainController(options, out reason);
        }
    }

    internal sealed class LdapSchemaHelper : ILdapSchemaHelper
    {
        public string GetSchemaNamingContext(LdapConnection ldapConnection)
        {
            try
            {
                var request = new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "schemaNamingContext");
                var response = (SearchResponse)ldapConnection.SendRequest(request);
                if (response.Entries.Count == 1)
                {
                    return response.Entries[0].Attributes["schemaNamingContext"][0].ToString();
                }

                throw new Exception("Unable to get schema naming context.");
            }
            catch (Exception ex)
            {
                AppConsole.WriteException(ex, "dc-schema: failed to read schemaNamingContext");
                return null;
            }
        }

        public Dictionary<string, string> GetAllAttributes(LdapConnection ldapConnection)
        {
            var attributeDictionary = new Dictionary<string, string>();
            string schemaNamingContext = GetSchemaNamingContext(ldapConnection);

            if (schemaNamingContext == null)
            {
                AppConsole.Log("dc-schema: schemaNamingContext is unavailable");
                return attributeDictionary;
            }

            try
            {
                var pageResultRequestControl = new PageResultRequestControl(1000);
                var searchRequest = new SearchRequest(schemaNamingContext, "(objectClass=attributeSchema)", SearchScope.Subtree, null);
                searchRequest.Controls.Add(pageResultRequestControl);

                while (true)
                {
                    var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);
                    foreach (SearchResultEntry entry in searchResponse.Entries)
                    {
                        string attributeName = entry.Attributes["lDAPDisplayName"][0].ToString();
                        string attributeSyntax = entry.Attributes["attributeSyntax"][0].ToString();
                        attributeDictionary[attributeName] = attributeSyntax;
                    }

                    var pageResponseControl = (PageResultResponseControl)searchResponse.Controls[0];
                    if (pageResponseControl.Cookie.Length == 0)
                    {
                        break;
                    }

                    pageResultRequestControl.Cookie = pageResponseControl.Cookie;
                }
            }
            catch (Exception ex)
            {
                AppConsole.WriteException(ex, "dc-schema: failed to load attribute schema entries");
            }

            return attributeDictionary;
        }
    }

    internal sealed class LdapConnectionFactory : ILdapConnectionFactory
    {
        private readonly IDomainControllerSelector _domainControllerSelector;

        public LdapConnectionFactory(IDomainControllerSelector domainControllerSelector)
        {
            _domainControllerSelector = domainControllerSelector;
        }

        public LdapConnection CreateBoundConnection(Options options)
        {
            var selectedDc = _domainControllerSelector.SelectBestDomainController(options, out var selectionReason);
            if (string.IsNullOrWhiteSpace(selectedDc))
            {
                throw new InvalidOperationException("Unable to select domain controller for LDAP connection.");
            }

            AppConsole.Log("dc-selected: " + selectedDc + " (reason: " + selectionReason + ")");

            var identifier = new LdapDirectoryIdentifier(selectedDc);
            var connection = new LdapConnection(identifier)
            {
                Timeout = TimeSpan.FromHours(1),
                AuthType = AuthType.Negotiate,
                AutoBind = true
            };

            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.AutoReconnect = true;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            TryConfigureKeepAlive(connection.SessionOptions);
            connection.SessionOptions.VerifyServerCertificate = new VerifyServerCertificateCallback((con, cer) => false);

            try
            {
                connection.Bind();
                AppConsole.Log("Successful bind to " + selectedDc + ".");
            }
            catch (LdapException e)
            {
                AppConsole.Log("[ERROR] LDAP bind failed for " + selectedDc + ": " + e.Message);
                throw;
            }

            return connection;
        }

        private static void TryConfigureKeepAlive(LdapSessionOptions sessionOptions)
        {
            TrySetSessionOption(sessionOptions, "PingKeepAliveTimeout", TimeSpan.FromMinutes(2));
            TrySetSessionOption(sessionOptions, "PingWaitTimeout", TimeSpan.FromSeconds(30));
            TrySetSessionOption(sessionOptions, "TcpKeepAlive", true);
        }

        private static void TrySetSessionOption(LdapSessionOptions sessionOptions, string propertyName, object value)
        {
            var propertyInfo = typeof(LdapSessionOptions).GetProperty(propertyName);
            if (propertyInfo == null || !propertyInfo.CanWrite)
            {
                return;
            }

            try
            {
                propertyInfo.SetValue(sessionOptions, value);
            }
            catch
            {
            }
        }
    }

    internal sealed class DomainControllerSelector : IDomainControllerSelector
    {
        private static readonly object DcSelectionLock = new object();
        private static readonly List<string> FallbackDomainControllers = new List<string>();
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

            var healthy = new List<DomainControllerProbeResult>();
            foreach (var candidate in discovered)
            {
                var probe = ProbeDomainController(candidate.Fqdn, TimeSpan.FromSeconds(3));
                if (probe.IsHealthy)
                {
                    probe.SiteName = candidate.SiteName;
                    healthy.Add(probe);
                }
                else
                {
                    AppConsole.Log("dc-probe-failed: " + candidate.Fqdn + " (" + probe.FailureReason + ")");
                }
            }

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

                if (selectedIndex == 0)
                {
                    reason = "best healthy DC by RTT" + (options.PreferSiteLocal ? " with local-site preference" : string.Empty);
                }
                else
                {
                    reason = "failover rotation to next healthy DC (index " + selectedIndex + "/" + FallbackDomainControllers.Count + ")";
                }

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
            string domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (string.IsNullOrWhiteSpace(domainName))
            {
                return result;
            }

            try
            {
                var domain = Domain.GetCurrentDomain();
                foreach (DomainController dc in domain.DomainControllers)
                {
                    var name = (dc.Name ?? string.Empty).Trim();
                    if (string.IsNullOrWhiteSpace(name))
                    {
                        continue;
                    }

                    result.Add(new DomainControllerCandidate
                    {
                        Fqdn = name,
                        SiteName = dc.SiteName
                    });
                }
            }
            catch (Exception ex)
            {
                AppConsole.Log("dc-discovery: failed via Domain.GetCurrentDomain(), fallback to domain name probe. " + ex.Message);
            }

            if (result.Count == 0)
            {
                result.Add(new DomainControllerCandidate
                {
                    Fqdn = domainName,
                    SiteName = null
                });
            }

            return result
                .GroupBy(x => x.Fqdn, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .ToList();
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
        }
    }
}
