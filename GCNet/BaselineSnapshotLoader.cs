using Newtonsoft.Json;
using Spectre.Console;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;

namespace GCNet
{
    internal interface IBaselineSnapshotLoader
    {
        void LoadInitialSnapshot(
            LdapConnection connection,
            string baseDn,
            IReadOnlyCollection<string> trackedAttributes,
            ConcurrentDictionary<string, BaselineEntry> baseline);
    }

    internal sealed class BaselineSnapshotLoader : IBaselineSnapshotLoader
    {
        private readonly ILdapEntryParser _entryParser;

        public BaselineSnapshotLoader(ILdapEntryParser entryParser)
        {
            _entryParser = entryParser;
        }

        public void LoadInitialSnapshot(
            LdapConnection connection,
            string baseDn,
            IReadOnlyCollection<string> trackedAttributes,
            ConcurrentDictionary<string, BaselineEntry> baseline)
        {
            var filter = "(|" + string.Join(string.Empty, trackedAttributes.Select(a => "(" + a + "=*)")) + ")";
            var attributes = new List<string> { "objectGUID", "distinguishedName" };
            attributes.AddRange(trackedAttributes);
            var request = new SearchRequest(baseDn, filter, SearchScope.Subtree, attributes.ToArray());
            request.Controls.Add(new PageResultRequestControl(1000));
            request.Controls.Add(new DomainScopeControl());

            var loadedCount = 0;

            AnsiConsole.Progress()
                .AutoClear(false)
                .HideCompleted(true)
                .Columns(new ProgressColumn[]
                {
                    new TaskDescriptionColumn(),
                    new SpinnerColumn()
                })
                .Start(ctx =>
                {
                    var task = ctx.AddTask("[green]Loading baseline[/]", autoStart: true);
                    task.IsIndeterminate = true;

                    while (true)
                    {
                        var response = (SearchResponse)connection.SendRequest(request);
                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            var guid = _entryParser.ReadObjectGuid(entry);
                            var objectKey = ObjectKeyBuilder.BuildObjectKey(guid, entry.DistinguishedName);

                            var snapshot = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                            var properties = _entryParser.ParseEntry(entry);
                            foreach (var attr in trackedAttributes)
                            {
                                snapshot[attr] = CanonicalizeAttribute(properties, attr);
                            }

                            baseline[objectKey] = new BaselineEntry
                            {
                                DistinguishedName = entry.DistinguishedName,
                                Attributes = snapshot
                            };

                            loadedCount++;
                            task.Description($"[green]Loading baseline[/] [grey](objects: {loadedCount})[/]");
                        }

                        var page = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault();
                        if (page == null || page.Cookie == null || page.Cookie.Length == 0)
                        {
                            break;
                        }

                        var pageRequest = request.Controls.OfType<PageResultRequestControl>().First();
                        pageRequest.Cookie = page.Cookie;
                    }

                    task.StopTask();
                });

            AppConsole.Log("Loaded baseline for objects: " + baseline.Count);
        }

        private static string CanonicalizeAttribute(Dictionary<string, object> properties, string attribute)
        {
            if (!properties.TryGetValue(attribute, out var value))
            {
                var actualKey = properties.Keys.FirstOrDefault(k => string.Equals(k, attribute, StringComparison.OrdinalIgnoreCase));
                if (actualKey == null)
                {
                    return "null";
                }

                value = properties[actualKey];
            }

            if (value == null)
            {
                return "null";
            }

            return JsonConvert.SerializeObject(value);
        }
    }
}
