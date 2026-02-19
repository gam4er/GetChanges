using Newtonsoft.Json;
using System;
using System.IO;
using System.Text;

namespace GCNet
{
    internal sealed class JsonArrayFileWriter : IDisposable
    {
        private readonly object _sync = new object();
        private readonly StreamWriter _streamWriter;
        private readonly JsonTextWriter _jsonWriter;
        private bool _completed;

        public JsonArrayFileWriter(string outputPath)
        {
            _streamWriter = new StreamWriter(outputPath, false, new UTF8Encoding(false));
            _jsonWriter = new JsonTextWriter(_streamWriter)
            {
                Formatting = Formatting.Indented,
                CloseOutput = false
            };

            _jsonWriter.WriteStartArray();
            _jsonWriter.Flush();
        }

        public void WriteObject(object obj)
        {
            lock (_sync)
            {
                if (_completed)
                {
                    return;
                }

                var serializer = JsonSerializer.CreateDefault();
                serializer.Serialize(_jsonWriter, obj);
                _jsonWriter.Flush();
                _streamWriter.Flush();
            }
        }

        public void Complete()
        {
            lock (_sync)
            {
                if (_completed)
                {
                    return;
                }

                _jsonWriter.WriteEndArray();
                _jsonWriter.Flush();
                _streamWriter.Flush();
                _completed = true;
            }
        }

        public void Dispose()
        {
            Complete();
            _jsonWriter.Dispose();
            _streamWriter.Dispose();
        }
    }
}
