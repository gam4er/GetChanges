using System.Collections.Generic;

namespace GCNet
{
    /// <summary>
    /// Snapshot of an AD object captured before notifications start. Stores canonical JSON
    /// representations of tracked attributes, used by <see cref="ChangeProcessingPipeline"/>
    /// to detect whether a notification carries an actual change to a tracked attribute.
    /// </summary>
    internal sealed class BaselineEntry
    {
        public string DistinguishedName { get; set; }

        /// <summary>Canonical JSON value per tracked attribute name (case-insensitive keys).</summary>
        public Dictionary<string, string> Attributes { get; set; }
    }
}
