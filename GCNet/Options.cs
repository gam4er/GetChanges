using CommandLine;

namespace GCNet
{
    internal class Options
    {
        public const string DefaultDnIgnoreListPath = "dn-ignore-default.txt";
        public const string DefaultOutputDirectoryPath = @".\output";

        [Option("base-dn", Required = false, HelpText = "Base DN for all searches. If omitted, defaultNamingContext is used.")]
        public string BaseDn { get; set; }

        [Option("enrich-metadata", Required = false, Default = false, HelpText = "Enrich events with msDS-ReplAttributeMetaData.")]
        public bool EnrichMetadata { get; set; }

        [Option("tracked-attributes", Required = false, HelpText = "Comma-separated attribute names. Metadata enrichment is executed only when these attributes are changed.")]
        public string TrackedAttributes { get; set; }

        [Option("dn-ignore-list", Required = false, Default = DefaultDnIgnoreListPath, HelpText = "Path to a file with DN filters to ignore (one per line).")]
        public string DnIgnoreListPath { get; set; }

        [Option("output-dir", Required = false, Default = DefaultOutputDirectoryPath, HelpText = "Directory path for JSON events (absolute or relative, e.g. .\\folder).")]
        public string OutputDirectory { get; set; }

        [Option("phantom-root", Required = false, Default = false, HelpText = "Enable LDAP SearchOption.PhantomRoot for notification search.")]
        public bool UsePhantomRoot { get; set; }

        [Option("dc", Required = false, HelpText = "Explicit domain controller FQDN to use for LDAP connections.")]
        public string DomainController { get; set; }

        [Option("dc-selection", Required = false, Default = "auto", HelpText = "Domain controller selection mode: auto or manual.")]
        public string DomainControllerSelectionMode { get; set; }

        [Option("prefer-site-local", Required = false, Default = true, HelpText = "Prefer healthy domain controllers in the local AD site.")]
        public bool PreferSiteLocal { get; set; }
    }
}
