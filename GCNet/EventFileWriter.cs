using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace GCNet
{
    internal sealed class EventFileWriter : IDisposable
    {
        private const int MaxFileStemLength = 180;
        private readonly object _sync = new object();
        private readonly string _outputDirectory;

        public EventFileWriter(string outputDirectory = null)
        {
            _outputDirectory = ResolveOutputDirectory(outputDirectory);
        }

        public void WriteEvent(Dictionary<string, object> evt)
        {
            if (evt == null)
            {
                return;
            }

            var distinguishedName = GetValueIgnoreCase(evt, "distinguishedName")?.ToString();
            var timestamp = ResolveTimestamp(evt);
            var timePart = timestamp.UtcDateTime.ToString("yyyyMMdd_HHmmss_fff");
            var dnPart = SanitizeFileComponent(string.IsNullOrWhiteSpace(distinguishedName) ? "unknown" : distinguishedName);
            lock (_sync)
            {
                var baseName = $"{timePart}_{dnPart}";
                var targetPath = GetUniquePath(baseName);
                using (var stream = new FileStream(targetPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                using (var jsonWriter = new JsonTextWriter(writer) { Formatting = Formatting.Indented })
                {
                    var serializer = JsonSerializer.CreateDefault();
                    serializer.Serialize(jsonWriter, evt);
                    jsonWriter.Flush();
                    writer.Flush();
                }
            }
        }

        private static object GetValueIgnoreCase(Dictionary<string, object> evt, string key)
        {
            if (evt.TryGetValue(key, out var exact))
            {
                return exact;
            }

            var match = evt.Keys.FirstOrDefault(k => string.Equals(k, key, StringComparison.OrdinalIgnoreCase));
            return match == null ? null : evt[match];
        }

        private static DateTimeOffset ResolveTimestamp(Dictionary<string, object> evt)
        {
            var value = GetValueIgnoreCase(evt, "timestamp");
            if (value is long longValue)
            {
                return DateTimeOffset.FromUnixTimeSeconds(longValue);
            }

            if (value is int intValue)
            {
                return DateTimeOffset.FromUnixTimeSeconds(intValue);
            }

            if (value is string stringValue && long.TryParse(stringValue, out var parsed))
            {
                return DateTimeOffset.FromUnixTimeSeconds(parsed);
            }

            return DateTimeOffset.UtcNow;
        }

        private static string ResolveOutputDirectory(string outputDirectory)
        {
            var configuredPath = string.IsNullOrWhiteSpace(outputDirectory)
                ? Options.DefaultOutputDirectoryPath
                : outputDirectory.Trim();

            var fullPath = Path.GetFullPath(configuredPath);
            if (File.Exists(fullPath))
            {
                throw new IOException("Output directory path points to an existing file: " + fullPath);
            }

            Directory.CreateDirectory(fullPath);
            return fullPath;
        }

        private string GetUniquePath(string baseName)
        {
            var safeBaseName = baseName;
            if (safeBaseName.Length > MaxFileStemLength)
            {
                safeBaseName = safeBaseName.Substring(0, MaxFileStemLength);
            }

            safeBaseName = safeBaseName.Trim().TrimEnd('.');
            if (string.IsNullOrWhiteSpace(safeBaseName))
            {
                safeBaseName = "event";
            }

            var candidate = Path.Combine(_outputDirectory, safeBaseName + ".json");
            if (!File.Exists(candidate))
            {
                return candidate;
            }

            for (var i = 1; i <= 10000; i++)
            {
                var indexed = Path.Combine(_outputDirectory, safeBaseName + "_" + i + ".json");
                if (!File.Exists(indexed))
                {
                    return indexed;
                }
            }

            return Path.Combine(_outputDirectory, safeBaseName + "_" + Guid.NewGuid().ToString("N") + ".json");
        }

        private static string SanitizeFileComponent(string value)
        {
            var invalid = Path.GetInvalidFileNameChars();
            var builder = new StringBuilder(value.Length);
            foreach (var ch in value)
            {
                builder.Append(invalid.Contains(ch) ? '_' : ch);
            }

            return builder
                .ToString()
                .Replace(" ", "_")
                .Trim('_');
        }

        public void Dispose()
        {
        }
    }
}
