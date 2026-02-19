using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Xml.Linq;

namespace GCNet
{
    internal sealed class MetadataEnricher
    {
        private readonly LdapConnection _connection;

        public MetadataEnricher(LdapConnection connection)
        {
            _connection = connection;
        }

        public IReadOnlyList<Dictionary<string, string>> LoadMetadata(string distinguishedName)
        {
            var request = new SearchRequest(
                distinguishedName,
                "(objectClass=*)",
                SearchScope.Base,
                "msDS-ReplAttributeMetaData");

            var response = (SearchResponse)_connection.SendRequest(request);
            var result = new List<Dictionary<string, string>>();

            if (response.Entries.Count == 0 || !response.Entries[0].Attributes.Contains("msDS-ReplAttributeMetaData"))
            {
                return result;
            }

            foreach (var raw in response.Entries[0].Attributes["msDS-ReplAttributeMetaData"].GetValues(typeof(string)))
            {
                var text = raw?.ToString();
                if (string.IsNullOrWhiteSpace(text))
                {
                    continue;
                }

                try
                {
                    var doc = XDocument.Parse(text);
                    result.Add(new Dictionary<string, string>
                    {
                        ["attributeName"] = doc.Root?.Element("pszAttributeName")?.Value,
                        ["version"] = doc.Root?.Element("dwVersion")?.Value,
                        ["lastChangeTime"] = doc.Root?.Element("ftimeLastOriginatingChange")?.Value,
                        ["changedBy"] = doc.Root?.Element("pszLastOriginatingDsaDN")?.Value,
                        ["raw"] = text
                    });
                }
                catch
                {
                    result.Add(new Dictionary<string, string>
                    {
                        ["raw"] = text,
                        ["parseError"] = "Unable to parse metadata XML"
                    });
                }
            }

            return result;
        }
    }
}
