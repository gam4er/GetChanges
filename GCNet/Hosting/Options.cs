using CommandLine;

using Spectre.Console.Cli;
using System.ComponentModel;

namespace GCNet
{
    internal sealed class Options : CommandSettings
    {
        public const string DefaultDnIgnoreListPath = "dn-ignore-default.txt";
        public const string DefaultOutputDirectoryPath = @".\output";

        [CommandOption("--base-dn")]
        [Description("Base DN for all searches. If omitted, defaultNamingContext is used.")]
        public string BaseDn { get; set; }

        [CommandOption("--enrich-metadata")]
        [Description("Enrich events with msDS-ReplAttributeMetaData.")]
        [DefaultValue(false)]
        public bool EnrichMetadata { get; set; }

        [CommandOption("--tracked-attributes")]
        [Description("Comma-separated attribute names. Metadata enrichment is executed only when these attributes are changed.")]
        public string TrackedAttributes { get; set; }

        [CommandOption("--track-nt-security-descriptor")]
        [Description("Track changes of nTSecurityDescriptor (Owner|Group|DACL). Implicitly enabled when --tracked-attributes contains nTSecurityDescriptor.")]
        [DefaultValue(false)]
        public bool TrackNtSecurityDescriptor { get; set; }

        [CommandOption("--dn-ignore-list")]
        [Description("Path to a file with DN filters to ignore (one per line).")]
        [DefaultValue(DefaultDnIgnoreListPath)]
        public string DnIgnoreListPath { get; set; } = DefaultDnIgnoreListPath;

        [CommandOption("--output-dir")]
        [Description("Directory path for JSON events (absolute or relative, e.g. .\\folder).")]
        [DefaultValue(DefaultOutputDirectoryPath)]
        public string OutputDirectory { get; set; } = DefaultOutputDirectoryPath;

        [CommandOption("--phantom-root")]
        [Description("Enable LDAP SearchOption.PhantomRoot for notification search.")]
        [DefaultValue(false)]
        public bool UsePhantomRoot { get; set; }

        [CommandOption("--dc")]
        [Description("Explicit domain controller FQDN to use for LDAP connections.")]
        public string DomainController { get; set; }

        [CommandOption("--dc-selection")]
        [Description("Domain controller selection mode: auto or manual.")]
        [DefaultValue("auto")]
        public string DomainControllerSelectionMode { get; set; } = "auto";

        [CommandOption("--prefer-site-local")]
        [Description("Prefer healthy domain controllers in the local AD site.")]
        [DefaultValue(true)]
        public bool PreferSiteLocal { get; set; } = true;
    }
}
