using CommandLine;

namespace GCNet
{
    internal class Options
    {
        [Option('o', "output", Required = false, Default = "result.json", HelpText = "Output JSON file path.")]
        public string OutputPath { get; set; }

        [Option("base-dn", Required = false, HelpText = "Base DN for all searches. If omitted, defaultNamingContext is used.")]
        public string BaseDn { get; set; }

        [Option("enrich-metadata", Required = false, Default = false, HelpText = "Enrich events with msDS-ReplAttributeMetaData.")]
        public bool EnrichMetadata { get; set; }

        [Option("tracked-attributes", Required = false, HelpText = "Comma-separated attribute names. Metadata enrichment is executed only when these attributes are changed.")]
        public string TrackedAttributes { get; set; }

        [Option("dn-ignore-list", Required = false, Default = "dn-ignore-default.txt", HelpText = "Path to a file with DN filters to ignore (one per line).")]
        public string DnIgnoreListPath { get; set; }
    }
}
