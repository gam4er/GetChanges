using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;

namespace GCNet
{
    internal interface ILdapEntryParser
    {
        Guid? ReadObjectGuid(SearchResultEntry entry);
        Task<Dictionary<string, object>> ParseEntryAsync(SearchResultEntry entry, CancellationToken cancellationToken);
    }

    internal sealed class LdapEntryParser : ILdapEntryParser
    {
        private readonly ILdapUtils _ldapUtils;
        private readonly LdapPropertyProcessor _processor;
        private readonly string _currentDomain;

        public LdapEntryParser()
            : this(new LdapUtils(), GetCurrentDomain())
        {
        }

        internal LdapEntryParser(ILdapUtils ldapUtils, string currentDomain)
        {
            _ldapUtils = ldapUtils ?? throw new ArgumentNullException(nameof(ldapUtils));
            _processor = new LdapPropertyProcessor(_ldapUtils);
            _currentDomain = currentDomain ?? string.Empty;
        }

        public Guid? ReadObjectGuid(SearchResultEntry entry)
        {
            if (!entry.Attributes.Contains("objectGUID"))
            {
                return null;
            }

            var bytes = entry.Attributes["objectGUID"][0] as byte[];
            if (bytes == null || bytes.Length == 0)
            {
                return null;
            }

            return new Guid(bytes);
        }

        public async Task<Dictionary<string, object>> ParseEntryAsync(SearchResultEntry entry, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var wrapper = new SearchResultEntryWrapper(entry);
            var properties = new Dictionary<string, object>(
                _processor.ParseAllProperties(wrapper),
                StringComparer.OrdinalIgnoreCase);
            var userProperties = await _processor.ReadUserProperties(wrapper, _currentDomain).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var p in userProperties.Props)
            {
                if (!properties.ContainsKey(p.Key))
                {
                    properties.Add(p.Key, p.Value);
                }
            }

            try
            {
                if (entry.Attributes.Contains("usercertificate"))
                {
                    var certificates = new List<ParsedCertificate>();
                    foreach (var certificateValue in entry.Attributes["usercertificate"])
                    {
                        if (certificateValue is byte[] certificateBytes)
                        {
                            certificates.Add(new ParsedCertificate(certificateBytes));
                        }
                    }

                    properties["usercertificate"] = certificates;
                }
            }
            catch (Exception ex)
            {
                AppConsole.WriteException(ex, "usercertificate parsing error");
            }

            try
            {
                if (entry.Attributes.Contains("msexchmailboxsecuritydescriptor"))
                {
                    var rawSecurityDescriptor = new RawSecurityDescriptor((byte[])entry.Attributes["msexchmailboxsecuritydescriptor"][0], 0);
                    properties["msexchmailboxsecuritydescriptor"] = rawSecurityDescriptor.GetSddlForm(AccessControlSections.All);
                }
            }
            catch (Exception ex)
            {
                AppConsole.WriteException(ex, "msexchmailboxsecuritydescriptor parsing error");
            }

            properties.Remove("thumbnailphoto");
            var pwdLastSetKey = properties.Keys.FirstOrDefault(k => string.Equals(k, "pwdLastSet", StringComparison.OrdinalIgnoreCase));
            if (pwdLastSetKey != null)
            {
                var pwdLastSetValue = properties[pwdLastSetKey];
                if ((pwdLastSetValue is long longValue && longValue == -1)
                    || (pwdLastSetValue is int intValue && intValue == -1)
                    || (pwdLastSetValue is string stringValue && stringValue == "-1"))
                {
                    properties[pwdLastSetKey] = null;
                }
            }

            properties["distinguishedName"] = entry.DistinguishedName;
            properties["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return properties;
        }

        private static string GetCurrentDomain()
        {
            return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
        }
    }
}
