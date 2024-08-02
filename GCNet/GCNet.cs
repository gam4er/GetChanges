using Newtonsoft.Json;

using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;

using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Net.NetworkInformation;
using System.Security.AccessControl;


namespace GCNet
{
    internal class GCNet
    {
        public static Dictionary<string, string> attributeDictionary = new Dictionary<string, string>();

        public static string GetCurrentDomain()
        {
            // Получаем информацию о сети
            var domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;

            // Если доменное имя пустое, выдаем сообщение об ошибке
            if (string.IsNullOrEmpty(domainName))
            {
                throw new InvalidOperationException("Не удалось определить домен текущего пользователя.");
            }

            return domainName;
        }

        public static void GetChangeNotifications(string searchBaseDN, LdapConnection connection)
        {
            try
            {
                string [] attributesToReturn = { "telephoneNumber", /*"objectGUID",*/ "uSNChanged", "NTSecurityDescriptor" };
                
                //SearchRequest searchRequest = new SearchRequest(searchBaseDN, "(objectClass=*)", SearchScope.Subtree, attributesToReturn);
                SearchRequest searchRequest = new SearchRequest(searchBaseDN, "(objectClass=*)", SearchScope.Subtree, null);


                DirectoryNotificationControl notificationControl = new DirectoryNotificationControl();
                notificationControl.IsCritical = true;
                notificationControl.ServerSide = true;
                searchRequest.Controls.Add(notificationControl);

                DirectoryControl LDAP_SERVER_LAZY_COMMIT_OID = new DirectoryControl("1.2.840.113556.1.4.619", null, true, true);
                searchRequest.Controls.Add(LDAP_SERVER_LAZY_COMMIT_OID);

                /*
                 * Нужны особые права 
                DirectoryControl dirSyncControl = new DirectoryControl("1.2.840.113556.1.4.841", null, true, true);
                searchRequest.Controls.Add(dirSyncControl);
                */

                DirectoryControl LDAP_SERVER_SHOW_DELETED_OID = new DirectoryControl("1.2.840.113556.1.4.417", null, true, true);
                searchRequest.Controls.Add(LDAP_SERVER_SHOW_DELETED_OID);


                DirectoryControl LDAP_SERVER_SHOW_RECYCLED_OID = new DirectoryControl("1.2.840.113556.1.4.2064", null, true, true);
                searchRequest.Controls.Add(LDAP_SERVER_SHOW_RECYCLED_OID);

                AsqRequestControl asqRequestControl = new AsqRequestControl();
                asqRequestControl.IsCritical = true; 
                asqRequestControl.ServerSide = true;
                asqRequestControl.AttributeName = "telephoneNumber";
                searchRequest.Controls.Add(asqRequestControl);

                /*
                 * К сожалению ACL не приходит
                 */
                var ReturnACL = new SecurityDescriptorFlagControl
                {
                    SecurityMasks = 
                    SecurityMasks.Dacl | 
                    SecurityMasks.Owner |
                    SecurityMasks.Group | 
                    SecurityMasks.Sacl
                };
                searchRequest.Controls.Add(ReturnACL);


                SearchOptionsControl searchOptions = new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.PhantomRoot);
                searchRequest.Controls.Add(searchOptions);


                AsyncCallback callback = new AsyncCallback(SearchResponseCallback);
                connection.BeginSendRequest(searchRequest, TimeSpan.FromSeconds(60*10), PartialResultProcessing.ReturnPartialResultsAndNotifyCallback, callback, connection);

                Console.WriteLine("Waiting for change notifications...");
                Console.ReadLine();
            }
            catch (LdapException e)
            {
                Console.WriteLine("LDAP error: " + e.Message);
            }
        }
        private static void SearchResponseCallback(IAsyncResult ar)
        {
            try
            {
                LdapConnection connection = (LdapConnection)ar.AsyncState;
                PartialResultsCollection response = connection.GetPartialResults(ar);
                foreach (SearchResultEntry entry in response)
                {
                    SearchResultEntryWrapper wrapper = new SearchResultEntryWrapper(entry);
                    ILdapUtils ldapUtils = new LdapUtils();
                    LdapPropertyProcessor processor = new LdapPropertyProcessor(ldapUtils);                            
                    Dictionary<string, object> properties = processor.ParseAllProperties(wrapper);
                    UserProperties userProperties = processor.ReadUserProperties(wrapper, GetCurrentDomain()).Result;

                    foreach (var p in userProperties.Props)                    
                        properties.Add(p.Key, p.Value);

                    try
                    {
                        properties ["usercertificate"] = new ParsedCertificate((byte [])entry.Attributes ["usercertificate"] [0] ?? new byte [] { });
                    }
                    catch (Exception e) { 
                        Console.WriteLine(e.Message);
                    }

                    try
                    {
                        if (entry.Attributes.Contains("msexchmailboxsecuritydescriptor"))
                        {
                            RawSecurityDescriptor rawSecurityDescriptor = new RawSecurityDescriptor((byte [])entry.Attributes ["msexchmailboxsecuritydescriptor"] [0] ?? new byte [] { }, 0);
                            string sddlString = rawSecurityDescriptor.GetSddlForm(AccessControlSections.All);
                            properties ["msexchmailboxsecuritydescriptor"] = sddlString;
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }

                    properties.Remove("thumbnailphoto");

                    //Console.WriteLine(JsonConvert.SerializeObject(properties, Newtonsoft.Json.Formatting.Indented));
                    File.AppendAllText("result.json", JsonConvert.SerializeObject(properties, Newtonsoft.Json.Formatting.Indented));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error in callback: " + e.Message);
            }
        }

        static void Main(string [] args)
        {
            LdapConnection connection = LDAPSearches.InitializeConnection();
            attributeDictionary = LDAPSearches.GetAllAttributes(connection);
            string searchBaseDN = LDAPSearches.GetUserOU();
            GetChangeNotifications(searchBaseDN, connection);
        }
    }
}
