using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;

using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace GCNet
{
    internal interface ILdapSchemaHelper
    {
        string GetSchemaNamingContext(LdapConnection ldapConnection);
        Dictionary<string, string> GetAllAttributes(LdapConnection ldapConnection);
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
            var attributeDictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var schemaNamingContext = GetSchemaNamingContext(ldapConnection);

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
                        var attributeName = entry.Attributes["lDAPDisplayName"][0].ToString();
                        var attributeSyntax = entry.Attributes["attributeSyntax"][0].ToString();
                        attributeDictionary[attributeName] = attributeSyntax;
                    }

                    var pageResponseControl = searchResponse.Controls[0] as PageResultResponseControl;
                    if (pageResponseControl == null || pageResponseControl.Cookie == null || pageResponseControl.Cookie.Length == 0)
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
}
