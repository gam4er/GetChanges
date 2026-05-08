using System;
using System.DirectoryServices.Protocols;

namespace GCNet
{
    /// <summary>
    /// Creates bound <see cref="LdapConnection"/> instances. Caches the selected domain controller
    /// so DC discovery runs only once at startup; <see cref="ResetCachedDomainController"/> is
    /// invoked by the notification loop to force rediscovery on reconnect.
    /// </summary>
    internal interface ILdapConnectionFactory
    {
        LdapConnection CreateBoundConnection(Options options);

        /// <summary>
        /// Drops the cached DC name. The next <see cref="CreateBoundConnection"/> call will
        /// re-run full domain controller discovery.
        /// </summary>
        void ResetCachedDomainController();
    }

    internal sealed class LdapConnectionFactory : ILdapConnectionFactory
    {
        private readonly IDomainControllerSelector _domainControllerSelector;
        // Lock guards both the cache field and the discovery call so two parallel reconnects
        // never race into a double-discovery storm.
        private readonly object _cacheLock = new object();
        private string _cachedDomainController;

        public LdapConnectionFactory(IDomainControllerSelector domainControllerSelector)
        {
            _domainControllerSelector = domainControllerSelector;
        }

        /// <inheritdoc/>
        public void ResetCachedDomainController()
        {
            lock (_cacheLock)
            {
                if (_cachedDomainController == null)
                {
                    return;
                }

                AppConsole.Log("dc-cache-reset: domain controller cache cleared, next connection will rediscover.");
                _cachedDomainController = null;
            }
        }

        public LdapConnection CreateBoundConnection(Options options)
        {
            string selectedDc;
            lock (_cacheLock)
            {
                if (_cachedDomainController == null)
                {
                    _cachedDomainController = _domainControllerSelector.SelectBestDomainController(options, out var selectionReason);
                    if (string.IsNullOrWhiteSpace(_cachedDomainController))
                    {
                        throw new InvalidOperationException("Unable to select domain controller for LDAP connection.");
                    }

                    AppConsole.Log("dc-selected: " + _cachedDomainController + " (reason: " + selectionReason + ")");
                }
                else
                {
                    AppConsole.Log("dc-using-cached: " + _cachedDomainController);
                }

                selectedDc = _cachedDomainController;
            }

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
            // SECURITY: certificate validation is intentionally disabled to support typical AD lab/internal
            // deployments where DCs use auto-enrolled certificates with chains the host may not trust.
            // For production / external deployments review this and supply a real validation callback.
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
            catch (Exception ex)
            {
                AppConsole.Log("ldap-session-option: unable to set " + propertyName + ". " + ex.Message);
            }
        }
    }
}
