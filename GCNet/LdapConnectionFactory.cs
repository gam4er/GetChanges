using System;
using System.DirectoryServices.Protocols;

namespace GCNet
{
    internal interface ILdapConnectionFactory
    {
        LdapConnection CreateBoundConnection(Options options);
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
            catch (Exception ex)
            {
                AppConsole.Log("ldap-session-option: unable to set " + propertyName + ". " + ex.Message);
            }
        }
    }
}
