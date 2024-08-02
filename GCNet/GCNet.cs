using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Threading;
using System.Xml;
using Newtonsoft.Json;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;


namespace GCNet
{
    internal class GCNet
    {
        public static Dictionary<string, string> attributeDictionary = new Dictionary<string, string>();

        public static void GetChangeNotifications(string searchBaseDN, LdapConnection connection)
        {
            try
            {
                string [] attributesToReturn = { "telephoneNumber", /*"objectGUID",*/ "uSNChanged", "NTSecurityDescriptor" };
                //SearchRequest searchRequest = new SearchRequest(searchBaseDN, "(telephoneNumber=*)", System.DirectoryServices.Protocols.SearchScope.Subtree, attributesToReturn);
                //SearchRequest searchRequest = new SearchRequest(searchBaseDN, "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Subtree, attributesToReturn);
                SearchRequest searchRequest = new SearchRequest(searchBaseDN, "(objectClass=*)", System.DirectoryServices.Protocols.SearchScope.Subtree, null);
                //SearchRequest searchRequest = new SearchRequest(searchBaseDN, "(&(logonCount=*)(objectClass=*))", System.DirectoryServices.Protocols.SearchScope.Subtree, attributesToReturn);
                //SearchRequest searchRequest = new SearchRequest(searchBaseDN, DSML, SearchScope.Subtree, attributesToReturn);

                DirectoryNotificationControl notificationControl = new DirectoryNotificationControl();
                notificationControl.IsCritical = true;
                notificationControl.ServerSide = true;
                searchRequest.Controls.Add(notificationControl);


                byte [] ssiBigEndian = BitConverter.GetBytes(0x00);
                // Проверяем порядок байтов и меняем его, если это необходимо
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(ssiBigEndian);
                }
                DirectoryControl DACLEnable = new DirectoryControl("1.2.840.113556.1.4.801", ssiBigEndian, true, true);
                //searchRequest.Controls.Add(DACLEnable);


                DirectoryControl LDAP_SERVER_LAZY_COMMIT_OID = new DirectoryControl("1.2.840.113556.1.4.619", null, true, true);
                searchRequest.Controls.Add(LDAP_SERVER_LAZY_COMMIT_OID);


                DirectoryControl dirSyncControl = new DirectoryControl("1.2.840.113556.1.4.841", null, true, true);
                //searchRequest.Controls.Add(dirSyncControl);

                DirectoryControl LDAP_SERVER_SHOW_DELETED_OID = new DirectoryControl("1.2.840.113556.1.4.417", null, true, true);
                searchRequest.Controls.Add(LDAP_SERVER_SHOW_DELETED_OID);


                DirectoryControl LDAP_SERVER_SHOW_RECYCLED_OID = new DirectoryControl("1.2.840.113556.1.4.2064", null, true, true);
                searchRequest.Controls.Add(LDAP_SERVER_SHOW_RECYCLED_OID);

                /*
                 * searchRequest.Controls.Add(new SecurityDescriptorFlagControl {
                 * SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                 * });
                 */

                var ReturnACL = new SecurityDescriptorFlagControl
                {
                    SecurityMasks = 
                    System.DirectoryServices.Protocols.SecurityMasks.Dacl | 
                    System.DirectoryServices.Protocols.SecurityMasks.Owner |
                    System.DirectoryServices.Protocols.SecurityMasks.Group | 
                    System.DirectoryServices.Protocols.SecurityMasks.Sacl
                };
                searchRequest.Controls.Add(ReturnACL);


                SearchOptionsControl searchOptions = new SearchOptionsControl(System.DirectoryServices.Protocols.SearchOption.PhantomRoot);
                searchRequest.Controls.Add(searchOptions);

                
                /*
                нет смысла в этом контроле, т.к. он не возвращает никаких данных
                DirectoryControl LDAP_SERVER_UPDATE_STATS_OID = new DirectoryControl("1.2.840.113556.1.4.2205", null, true, true);
                searchRequest.Controls.Add(LDAP_SERVER_UPDATE_STATS_OID);
                */

                AsyncCallback callback = new AsyncCallback(SearchResponseCallback);
                connection.BeginSendRequest(searchRequest, TimeSpan.FromSeconds(60*10), PartialResultProcessing.ReturnPartialResultsAndNotifyCallback, callback, connection);
                
                /*
                AsyncCallback callback = new AsyncCallback(SearchResponseCallbacktoJSON);
                connection.BeginSendRequest(searchRequest, TimeSpan.FromSeconds(60 * 10), PartialResultProcessing.ReturnPartialResultsAndNotifyCallback, callback, connection);
                */

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

                //var response = connection.EndSendRequest(ar);
                //foreach (SearchResultEntry entry in ((SearchResponse)response).Entries)
                PartialResultsCollection response = connection.GetPartialResults(ar);                
                //var EndR = connection.EndSendRequest(ar);

                foreach (SearchResultEntry entry in response)
                {
                    //entry.Attributes.AttributeNames.Cast<string>().ToList().ForEach(Console.WriteLine);
                    /*
                    if (!entry.DistinguishedName.Contains("Rodchenko"))
                        continue;
                    
                    Console.WriteLine("Distinguished Name: " + entry.DistinguishedName);

                    foreach (string attributeName in entry.Attributes.AttributeNames)                    
                        Console.WriteLine("    {0}: {1}", attributeName, string.Join(", ", entry.Attributes[attributeName].GetValues(typeof(string))));
                    */
                    File.WriteAllText("result.json", SerializeSearchResultEntry(entry));
                    Console.WriteLine(SerializeSearchResultEntry(entry));
                    //SerializeSearchResultEntry(entry);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error in callback: " + e.Message);
            }
        }
        public static string SerializeSearchResultEntry(SearchResultEntry entry)
        {
            var entryDict = new Dictionary<string, object>
            {
                { "DistinguishedName", entry.DistinguishedName }
            };

            foreach (string attributeName in entry.Attributes.AttributeNames)
            {
                try
                {
                    string attributeType = attributeDictionary [attributeName];

                    if (attributeType != null)
                    {
                        entryDict [attributeName] = GetTypedAttributeValues(entry.Attributes [attributeName], attributeType);
                    }
                    else
                    {
                        entryDict [attributeName] = GetReadableAttributeValues(entry.Attributes [attributeName]);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: " + e.Message);
                }
            }

            return JsonConvert.SerializeObject(entryDict, Newtonsoft.Json.Formatting.Indented);
        }
        public static object GetTypedAttributeValues(DirectoryAttribute attribute, string attributeType)
        {
            var values = new List<object>();
            switch (attributeType)
            {
                case "Boolean":
                    values.AddRange(new List<string> { attribute.GetValues(typeof(string)).ToString() });
                    break;
                case "Integer":
                case "String(Numeric)":
                    values.AddRange(attribute.GetValues(typeof(int)));
                    break;
                case "Integer64":
                case "LargeInteger":
                    values.AddRange(attribute.GetValues(typeof(Int64)));
                    break;
                case "String(Unicode)":
                case "String(Printable)":
                case "String(Teletex)":
                case "String(IA5)":
                case "String(Case sensitive)":
                case "String(Octet)":                
                case "String(UTC Time)":
                case "String(Generalized Time)":
                    values.AddRange(attribute.GetValues(typeof(string)).Select(v => v.ToString()));
                    break;
                case "DN":
                case "OID":
                    values.AddRange(attribute.GetValues(typeof(string)).Select(v => v.ToString()));
                    break;
                case "String(NT-Sec-Desc)":
                case "String(Sid)":
                    values.AddRange(attribute.GetValues(typeof(byte [])).Select(v => new SecurityIdentifier((byte [])v, 0)));
                    break;
                default:
                    values.AddRange(attribute.GetValues(typeof(object)).Select(v => v.ToString()));
                    break;
            }

            return values.Count > 1 ? (object)values : values [0];
        }

        public static object GetReadableAttributeValues(DirectoryAttribute attribute)
        {
            var values = new List<object>();

            var stringValues = attribute.GetValues(typeof(string));
            if (stringValues != null && stringValues.Length > 0)
            {
                values.AddRange(stringValues.Select(v => v.ToString()));
            }
            else
            {
                var byteValues = attribute.GetValues(typeof(byte []));
                if (byteValues != null && byteValues.Length > 0)
                {
                    values.AddRange(byteValues.Select(v => Convert.ToBase64String((byte [])v)));
                }
                else
                {
                    values.AddRange(attribute.GetValues(typeof(string)).Select(v => v.ToString()));
                }
            }

            return values.Count > 1 ? (object)values : values [0];
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
