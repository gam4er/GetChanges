using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace GCNet
{
    internal static class FilterLoader
    {
        public static IReadOnlyList<string> Load(string path)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException("LDAP filters file was not found", path);
            }

            return File.ReadAllLines(path)
                .Select(x => x.Trim())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Where(x => !x.StartsWith("#"))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(5)
                .ToList();
        }
    }
}
