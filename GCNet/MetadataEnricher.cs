using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Xml.Linq;

namespace GCNet
{
    internal interface IMetadataEnricher
    {
        MetadataEnrichmentResult TryLoadMetadata(string distinguishedName);
    }

    internal sealed class MetadataEnrichmentResult
    {
        public IReadOnlyList<Dictionary<string, string>> Metadata { get; set; }
        public string Error { get; set; }
        public bool HasError => !string.IsNullOrWhiteSpace(Error);
    }

    internal sealed class MetadataEnricher : IMetadataEnricher, IDisposable
    {
        private readonly Func<LdapConnection> _connectionFactory;
        private readonly object _sync = new object();
        private LdapConnection _connection;

        public MetadataEnricher(Func<LdapConnection> connectionFactory)
        {
            _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        }

        public MetadataEnrichmentResult TryLoadMetadata(string distinguishedName)
        {
            var result = new List<Dictionary<string, string>>();
            try
            {
                var response = SendMetadataRequest(distinguishedName, allowReconnect: true);
                if (response.Entries.Count == 0 || !response.Entries[0].Attributes.Contains("msDS-ReplAttributeMetaData"))
                {
                    return new MetadataEnrichmentResult { Metadata = result };
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

                return new MetadataEnrichmentResult { Metadata = result };
            }
            catch (Exception ex)
            {
                return new MetadataEnrichmentResult
                {
                    Metadata = result,
                    Error = ex.GetType().Name + ": " + ex.Message
                };
            }
        }

        public void Dispose()
        {
            lock (_sync)
            {
                _connection?.Dispose();
                _connection = null;
            }
        }

        private SearchResponse SendMetadataRequest(string distinguishedName, bool allowReconnect)
        {
            try
            {
                var request = new SearchRequest(
                    distinguishedName,
                    "(objectClass=*)",
                    SearchScope.Base,
                    "msDS-ReplAttributeMetaData");
                return (SearchResponse)GetConnection().SendRequest(request);
            }
            catch when (allowReconnect)
            {
                ResetConnection();
                return SendMetadataRequest(distinguishedName, allowReconnect: false);
            }
        }

        private LdapConnection GetConnection()
        {
            lock (_sync)
            {
                if (_connection == null)
                {
                    _connection = _connectionFactory();
                }

                return _connection;
            }
        }

        private void ResetConnection()
        {
            lock (_sync)
            {
                _connection?.Dispose();
                _connection = null;
            }
        }
    }
}
