using System;
using System.Security.Cryptography;
using System.Text;

namespace GCNet
{
    internal static class ObjectKeyBuilder
    {
        public static string BuildObjectKey(Guid? objectGuid, string distinguishedName)
        {
            if (objectGuid.HasValue)
            {
                return "guid:" + objectGuid.Value.ToString("N").ToLowerInvariant();
            }

            return "dn-md5:" + ComputeDnHash(distinguishedName);
        }

        private static string ComputeDnHash(string distinguishedName)
        {
            var normalizedDn = (distinguishedName ?? string.Empty).Trim().ToLowerInvariant();
            using (var md5 = MD5.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(normalizedDn);
                var hash = md5.ComputeHash(bytes);
                return ToHexLower(hash);
            }
        }

        private static string ToHexLower(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                builder.Append(b.ToString("x2"));
            }

            return builder.ToString();
        }
    }
}
