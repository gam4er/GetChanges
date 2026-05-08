using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;

namespace GCNet
{
    /// <summary>
    /// Single AD object change observed via LDAP persistent search.
    /// Carries both the raw <see cref="SearchResultEntry"/> and the parsed property bag
    /// produced by <see cref="LdapEntryParser"/>.
    /// </summary>
    internal sealed class ChangeEvent
    {
        /// <summary>Stable AD object identity (objectGUID).</summary>
        public Guid? ObjectGuid { get; set; }

        public string DistinguishedName { get; set; }

        /// <summary>Raw LDAP entry. Useful for re-parsing or additional metadata extraction downstream.</summary>
        public SearchResultEntry Entry { get; set; }

        /// <summary>Parsed attributes that will be serialised to JSON.</summary>
        public Dictionary<string, object> Properties { get; set; }
    }
}
