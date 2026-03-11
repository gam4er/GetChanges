using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;

namespace GCNet
{
    internal sealed class ChangeEvent
    {
        public Guid? ObjectGuid { get; set; }
        public string DistinguishedName { get; set; }
        public SearchResultEntry Entry { get; set; }
        public Dictionary<string, object> Properties { get; set; }
    }

    internal sealed class BaselineEntry
    {
        public string DistinguishedName { get; set; }
        public Dictionary<string, string> Attributes { get; set; }
    }
}
