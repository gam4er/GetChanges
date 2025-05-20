using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Net.NetworkInformation;

namespace GCNet
{
    internal class LDAPSearches
    {
        public static string GetSchemaNamingContext(LdapConnection ldapConnection)
        {
            try
            {
                // Запрос RootDSE для получения схемы DN
                var request = new SearchRequest(
                    null, // RootDSE имеет null как base DN
                    "(objectClass=*)",
                    System.DirectoryServices.Protocols.SearchScope.Base,
                    "schemaNamingContext");

                var response = (SearchResponse)ldapConnection.SendRequest(request);
                if (response.Entries.Count == 1)
                {
                    return response.Entries [0].Attributes ["schemaNamingContext"] [0].ToString();
                }
                else
                {
                    throw new Exception("Unable to get schema naming context.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return null;
            }
        }

        public static Dictionary<string, string> GetAllAttributes(LdapConnection ldapConnection)
        {
            var attributeDictionary = new Dictionary<string, string>();
            string schemaNamingContext = GetSchemaNamingContext(ldapConnection);

            if (schemaNamingContext == null)
            {
                Console.WriteLine("Failed to retrieve schema naming context.");
                return attributeDictionary;
            }

            try
            {
                // Используем пагинацию для получения всех атрибутов
                var pageResultRequestControl = new PageResultRequestControl(1000);
                var searchRequest = new SearchRequest(
                schemaNamingContext,
                "(objectClass=attributeSchema)",
                System.DirectoryServices.Protocols.SearchScope.Subtree,
                null);
                searchRequest.Controls.Add(pageResultRequestControl);

                while (true)
                {
                    var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);

                    foreach (SearchResultEntry entry in searchResponse.Entries)
                    {
                        string attributeName = entry.Attributes ["lDAPDisplayName"] [0].ToString();
                        if (attributeName == "directReports")
                        {
                            Console.WriteLine("directReports attribute.");
                        }
                        string attributeSyntax = entry.Attributes ["attributeSyntax"] [0].ToString();
                        attributeDictionary [attributeName] = attributeSyntax;
                    }

                    var pageResponseControl = (PageResultResponseControl)searchResponse.Controls [0];
                    if (pageResponseControl.Cookie.Length == 0)
                    {
                        break;
                    }

                    pageResultRequestControl.Cookie = pageResponseControl.Cookie;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            return attributeDictionary;
        }

        public static string GetUserOU()
        {
            var user = UserPrincipal.Current;
            DirectoryEntry deUser = user.GetUnderlyingObject() as DirectoryEntry;
            DirectoryEntry deUserContainer = deUser.Parent;
            return deUserContainer.Properties ["distinguishedName"].Value.ToString();
        }
        public static LdapConnection InitializeConnection()
        {
            string domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;

            if (string.IsNullOrEmpty(domainName))
            {
                Console.WriteLine("Не удалось определить домен текущего пользователя.");
                return null;
            }

            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainName);
            LdapConnection connection = new LdapConnection(identifier);

            connection.SessionOptions.ProtocolVersion = 3;
            connection.AuthType = AuthType.Negotiate;
            connection.SessionOptions.AutoReconnect = true;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            connection.SessionOptions.VerifyServerCertificate = new VerifyServerCertificateCallback((con, cer) => false);
            connection.AutoBind = true;
            connection.SessionOptions.LocatorFlag = LocatorFlags.KdcRequired | LocatorFlags.PdcRequired;
            //connection.SessionOptions.Sealing = false;
            //connection.SessionOptions.Signing = false;
            //connection.SessionOptions.SecureSocketLayer = false;

            try
            {
                connection.Bind();
                Console.WriteLine("Successful bind.");
            }
            catch (LdapException e)
            {
                Console.WriteLine("LDAP error: " + e.Message);
                throw;
            }

            return connection;
        }

    }
}
