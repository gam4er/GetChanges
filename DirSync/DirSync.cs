using System;
using System.DirectoryServices.Protocols;
using System.Net.NetworkInformation;

namespace DirSync
{
    internal class DirSync
    {
        static void Main(string [] args)
        {
            try
            {
                string domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;
                LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainName);
                LdapConnection connection = new LdapConnection(identifier)
                {
                    AuthType = AuthType.Negotiate,
                    SessionOptions = { ProtocolVersion = 3 }
                };

                connection.Bind();

                // Create DirSync control
                byte [] dirSyncCookie = null; // Initialize with null for the first request
                DirectoryControl dirSyncControl = new DirectoryControl("1.2.840.113556.1.4.841", dirSyncCookie, true, true);

                // Create search request with DirSync control
                string searchFilter = "(objectClass=*)";
                SearchRequest searchRequest = new SearchRequest("", searchFilter, SearchScope.Subtree, null);
                searchRequest.Controls.Add(dirSyncControl);

                // Send search request and get response
                SearchResponse searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                // Process search results
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    Console.WriteLine("Distinguished Name: " + entry.DistinguishedName);
                    foreach (string attributeName in entry.Attributes.AttributeNames)
                    {
                        var values = entry.Attributes [attributeName].GetValues(typeof(string));
                        Console.WriteLine($"    {attributeName}: {string.Join(", ", values)}");
                    }
                }

                // Update dirSyncCookie for next request
                foreach (DirectoryControl control in searchResponse.Controls)
                {
                    if (control.Type == "1.2.840.113556.1.4.841")
                    {
                        dirSyncCookie = control.GetValue();
                    }
                }
            }
            catch (LdapException ex)
            {
                Console.WriteLine("LDAP error: " + ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }    
}
