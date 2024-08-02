using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
//using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Sharphound.Writers
{
    // MetaTag class
    public class MetaTag
    {
        public int Count { get; set; }
        public long CollectionMethods { get; set; }
        public string DataType { get; set; }
        public int Version { get; set; }
        public string CollectorVersion { get; set; }
    }

    // Flags class
    public class Flags
    {
        public bool NoOutput { get; set; }
        public bool PrettyPrint { get; set; }
    }

    // FileExistsException class
    internal class FileExistsException : Exception
    {
        public FileExistsException(string message) : base(message) { }
    }

    // BaseWriter abstract class
    public abstract class BaseWriter<T>
    {
        protected readonly string DataType;
        protected readonly List<T> Queue;
        protected bool FileCreated;
        protected int Count;
        protected bool NoOp;

        internal BaseWriter(string dataType)
        {
            DataType = dataType;
            Queue = new List<T>();
        }

        internal void AcceptObjects(List<T> items)
        {
            if (NoOp)
                return;
            if (!FileCreated)
            {
                CreateFile();
                FileCreated = true;
            }

            Queue.AddRange(items);
            Count += items.Count;
            WriteData();
            Queue.Clear();
        }
        protected abstract void WriteData();

        internal abstract void FlushWriter();

        protected abstract void CreateFile();
    }

    // JsonDataWriter class
    public class JsonDataWriter<T> : BaseWriter<T>
    {
        private JsonTextWriter _jsonWriter;
        private string _fileName;
        private JsonSerializerSettings _serializerSettings;

        private const int DataVersion = 6;

        public JsonDataWriter(string dataType) : base(dataType)
        {
            _serializerSettings = new JsonSerializerSettings
            {
                Converters = new List<JsonConverter> { new StringEnumConverter() },
                Formatting = Newtonsoft.Json.Formatting.Indented
            };
        }

        protected override void CreateFile()
        {
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
            var filename = $"results_{timestamp}.json";
            if (File.Exists(filename))
                throw new FileExistsException($"File {filename} already exists.");

            _fileName = filename;

            _jsonWriter = new JsonTextWriter(new StreamWriter(filename, false, new UTF8Encoding(false)))
            {
                Formatting = Formatting.Indented
            };
            _jsonWriter.WriteStartObject();
            _jsonWriter.WritePropertyName("data");
            _jsonWriter.WriteStartArray();
        }

        protected override void WriteData()
        {
            foreach (var item in Queue)
            {
                _jsonWriter.WriteRawValue(JsonConvert.SerializeObject(item, _serializerSettings));
            }
        }

        internal override void FlushWriter()
        {
            if (!FileCreated)
                return;

            if (Queue.Count > 0)
            {
                WriteData();
            }

            var meta = new MetaTag
            {
                Count = Count,
                CollectionMethods = 0,
                DataType = DataType,
                Version = DataVersion,
                CollectorVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString()
            };

            _jsonWriter.Flush();
            _jsonWriter.WriteEndArray();
            _jsonWriter.WritePropertyName("meta");
            _jsonWriter.WriteRawValue(JsonConvert.SerializeObject(meta, Newtonsoft.Json.Formatting.Indented));
            _jsonWriter.Flush();
            _jsonWriter.Close();
        }

        internal string GetFilename()
        {
            return FileCreated ? _fileName : null;
        }
    }

    // Main Program class for example usage
    public class Program
    {
        public static LdapConnection InitializeConnection()
        {
            string domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;

            if (string.IsNullOrEmpty(domainName))
            {
                Console.WriteLine("Не удалось определить домен текущего пользователя.");
                return null;
            }

            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainName);
            LdapConnection connection = new LdapConnection(identifier);

            connection.SessionOptions.ProtocolVersion = 3;
            connection.AuthType = AuthType.Negotiate;
            connection.SessionOptions.AutoReconnect = true;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            connection.SessionOptions.VerifyServerCertificate = new VerifyServerCertificateCallback((con, cer) => false);
            connection.AutoBind = true;
            connection.SessionOptions.LocatorFlag = LocatorFlags.KdcRequired | LocatorFlags.PdcRequired;
            //connection.SessionOptions.Sealing = false;
            //connection.SessionOptions.Signing = false;
            //connection.SessionOptions.SecureSocketLayer = false;

            try
            {
                connection.Bind();
                Console.WriteLine("Successful bind.");
            }
            catch (LdapException e)
            {
                Console.WriteLine("LDAP error: " + e.Message);
                throw;
            }

            return connection;
        }

        public static void Main(string [] args)
        {
            var writer = new JsonDataWriter<SearchResultEntry>("searchresults");

            LdapConnection connection = InitializeConnection();

            var users = new List<SearchResultEntry>();
            string schemaNamingContext = "OU=Accounts,OU=Clients,DC=avp,DC=ru";

            if (schemaNamingContext == null)
            {
                Console.WriteLine("Failed to retrieve schema naming context.");
                return ;
            }

            try
            {
                // Используем пагинацию для получения всех атрибутов
                var pageResultRequestControl = new PageResultRequestControl(1000);
                var searchRequest = new SearchRequest(
                    schemaNamingContext,
                    "(objectClass=*)",
                    SearchScope.Subtree,
                    null);
                searchRequest.Controls.Add(pageResultRequestControl);

                while (true)
                {
                    var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                    foreach (SearchResultEntry entry in searchResponse.Entries)
                    {
                        users.Add(entry);
                    }

                    var pageResponseControl = (PageResultResponseControl)searchResponse.Controls [0];
                    if (pageResponseControl.Cookie.Length == 0)
                    {
                        break;
                    }

                    pageResultRequestControl.Cookie = pageResponseControl.Cookie;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }


            writer.AcceptObjects(users);
            writer.FlushWriter();
        }
    }
}
