using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace GCNet
{
    internal static class CanonicalValueHelper
    {
        public static string Serialize(object value)
        {
            return value == null ? "null" : JsonConvert.SerializeObject(value);
        }

        public static object Deserialize(string canonical)
        {
            if (string.IsNullOrWhiteSpace(canonical))
            {
                return null;
            }

            var token = JToken.Parse(canonical);
            if (token.Type == JTokenType.Array)
            {
                return token.ToObject<List<object>>();
            }

            if (token.Type == JTokenType.Null)
            {
                return null;
            }

            return token.ToObject<object>();
        }
    }
}
