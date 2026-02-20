using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.AccessControl;

namespace GCNet
{
    internal interface ILdapEntryParser
    {
        Guid? ReadObjectGuid(SearchResultEntry entry);
        Dictionary<string, object> ParseEntry(SearchResultEntry entry);
    }

    internal sealed class LdapEntryParser : ILdapEntryParser
    {
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

        public Dictionary<string, object> ParseEntry(SearchResultEntry entry)
        {
            var wrapper = new SearchResultEntryWrapper(entry);
            ILdapUtils ldapUtils = new LdapUtils();
            var processor = new LdapPropertyProcessor(ldapUtils);
            var properties = processor.ParseAllProperties(wrapper);
            var userProperties = processor.ReadUserProperties(wrapper, GetCurrentDomain()).Result;

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
