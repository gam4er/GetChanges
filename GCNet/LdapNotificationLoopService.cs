using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using SearchOption = System.DirectoryServices.Protocols.SearchOption;

namespace GCNet
{
    internal interface ILdapNotificationLoopService
    {
        Task RunAsync(NotificationLoopContext context, CancellationToken cancellationToken);
    }

    internal sealed class NotificationLoopContext
    {
        public string BaseDn { get; set; }
        public Func<LdapConnection> ConnectionFactory { get; set; }
        public BlockingCollection<ChangeEvent> Target { get; set; }
        public IReadOnlyCollection<string> DnIgnoreFilters { get; set; }
        public bool UsePhantomRoot { get; set; }
        public Action OnNotificationReceived { get; set; }
    }

    internal sealed class LdapNotificationLoopService : ILdapNotificationLoopService
    {
        private readonly ILdapEntryParser _entryParser;
        private static readonly object BackoffRandomLock = new object();
        private static readonly Random BackoffRandom = new Random();

        public LdapNotificationLoopService(ILdapEntryParser entryParser)
        {
            _entryParser = entryParser;
        }

        public Task RunAsync(NotificationLoopContext context, CancellationToken cancellationToken)
        {
            var attempt = 0;

            while (!cancellationToken.IsCancellationRequested)
            {
                LdapConnection sessionConnection = null;
                NotificationSubscription subscription = null;
                var restartSignal = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                try
                {
                    AppConsole.Log("connect: creating LDAP notification session");
                    sessionConnection = context.ConnectionFactory();

                    var request = BuildNotificationRequest(context.BaseDn, context.UsePhantomRoot);
                    subscription = new NotificationSubscription(
                        sessionConnection,
                        request,
                        context.Target,
                        context.DnIgnoreFilters,
                        cancellationToken,
                        _entryParser,
                        context.OnNotificationReceived,
                        ex =>
                        {
                            AppConsole.WriteException(ex, "callback-fail: recoverable LDAP notification error." + BuildLdapDiagnostics(ex));
                            restartSignal.TrySetResult(true);
                        });

                    AppConsole.Log("subscribe: starting LDAP change notification subscription");
                    subscription.Start();

                    AppConsole.Log("reconnect-success: LDAP notification session is active");
                    attempt = 0;

                    WaitForRestartOrCancellation(restartSignal.Task, cancellationToken);
                }
                catch (Exception ex) when (IsRecoverableNotificationException(ex))
                {
                    AppConsole.WriteException(ex, "callback-fail: recoverable session error while starting/serving notifications." + BuildLdapDiagnostics(ex));
                }
                finally
                {
                    subscription?.Dispose();
                    sessionConnection?.Dispose();
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                attempt++;
                var delay = CalculateReconnectDelay(attempt);
                AppConsole.Log("reconnect-attempt: waiting " + delay + " before creating new LDAP session");
                try
                {
                    Task.Delay(delay, cancellationToken).Wait(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            return Task.CompletedTask;
        }

        private sealed class NotificationSubscription : IDisposable
        {
            private readonly LdapConnection _connection;
            private readonly SearchRequest _request;
            private readonly BlockingCollection<ChangeEvent> _target;
            private readonly IReadOnlyCollection<string> _dnIgnoreFilters;
            private readonly CancellationToken _cancellationToken;
            private readonly ILdapEntryParser _entryParser;
            private readonly Action _onNotificationReceived;
            private readonly Action<Exception> _onError;
            private IAsyncResult _asyncResult;
            private int _stopped;

            public NotificationSubscription(
                LdapConnection connection,
                SearchRequest request,
                BlockingCollection<ChangeEvent> target,
                IReadOnlyCollection<string> dnIgnoreFilters,
                CancellationToken cancellationToken,
                ILdapEntryParser entryParser,
                Action onNotificationReceived,
                Action<Exception> onError)
            {
                _connection = connection;
                _request = request;
                _target = target;
                _dnIgnoreFilters = dnIgnoreFilters;
                _cancellationToken = cancellationToken;
                _entryParser = entryParser;
                _onNotificationReceived = onNotificationReceived;
                _onError = onError;
            }

            public void Start()
            {
                _asyncResult = _connection.BeginSendRequest(
                    _request,
                    TimeSpan.FromDays(1),
                    PartialResultProcessing.ReturnPartialResultsAndNotifyCallback,
                    OnPartialResults,
                    _connection);
            }

            public void Stop()
            {
                if (Interlocked.Exchange(ref _stopped, 1) == 1)
                {
                    return;
                }

                try
                {
                    if (_asyncResult != null)
                    {
                        _connection.Abort(_asyncResult);
                    }
                }
                catch (Exception)
                {
                }
            }

            public void Dispose()
            {
                Stop();
            }

            private void OnPartialResults(IAsyncResult ar)
            {
                if (Volatile.Read(ref _stopped) == 1 || _cancellationToken.IsCancellationRequested)
                {
                    return;
                }

                try
                {
                    var partialResults = _connection.GetPartialResults(ar);
                    for (int i = 0; i < partialResults.Count; i++)
                    {
                        if (_cancellationToken.IsCancellationRequested)
                        {
                            return;
                        }

                        var entry = partialResults[i] as SearchResultEntry;
                        if (entry == null)
                        {
                            continue;
                        }

                        var entryDn = (entry.DistinguishedName ?? string.Empty).ToLowerInvariant();
                        if (ShouldIgnoreByDn(entryDn, _dnIgnoreFilters))
                        {
                            continue;
                        }

                        var properties = _entryParser.ParseEntry(entry);
                        if (properties == null)
                        {
                            continue;
                        }

                        _target.Add(new ChangeEvent
                        {
                            DistinguishedName = entry.DistinguishedName,
                            ObjectGuid = _entryParser.ReadObjectGuid(entry),
                            Properties = properties
                        }, _cancellationToken);

                        _onNotificationReceived();
                    }
                }
                catch (Exception ex)
                {
                    _onError(ex);
                }
            }
        }

        private static SearchRequest BuildNotificationRequest(string baseDn, bool usePhantomRoot)
        {
            var request = new SearchRequest(baseDn, "(objectClass=*)", SearchScope.Subtree, null);
            request.Controls.Add(new DirectoryNotificationControl { IsCritical = true, ServerSide = true });
            request.Controls.Add(new DomainScopeControl());
            request.Controls.Add(new DirectoryControl("1.2.840.113556.1.4.417", null, true, true));
            request.Controls.Add(new DirectoryControl("1.2.840.113556.1.4.2064", null, true, true));

            if (usePhantomRoot)
            {
                request.Controls.Add(new SearchOptionsControl(SearchOption.PhantomRoot));
            }

            return request;
        }

        private static bool ShouldIgnoreByDn(string dn, IReadOnlyCollection<string> filters)
        {
            if (string.IsNullOrWhiteSpace(dn) || filters == null || filters.Count == 0)
            {
                return false;
            }

            foreach (var filter in filters)
            {
                if (dn.Contains(filter))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsRecoverableNotificationException(Exception ex)
        {
            return ex is LdapException
                || ex is DirectoryOperationException
                || ex is ObjectDisposedException
                || ex is IOException
                || ex.InnerException is LdapException
                || ex.InnerException is DirectoryOperationException
                || ex.InnerException is IOException;
        }

        private static TimeSpan CalculateReconnectDelay(int attempt)
        {
            var cappedAttempt = Math.Min(attempt, 6);
            var baseDelaySeconds = Math.Pow(2, Math.Max(0, cappedAttempt - 1));
            double jitter;
            lock (BackoffRandomLock)
            {
                jitter = BackoffRandom.NextDouble() * 0.2;
            }

            return TimeSpan.FromSeconds(Math.Min(60, baseDelaySeconds * (1.0 + jitter)));
        }

        private static void WaitForRestartOrCancellation(Task restartTask, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (restartTask.Wait(TimeSpan.FromMilliseconds(250)))
                {
                    return;
                }
            }
        }

        private static string BuildLdapDiagnostics(Exception ex)
        {
            var diagnostics = new StringBuilder();
            diagnostics.Append("LDAP HResult: 0x").Append(ex.HResult.ToString("X8")).Append(" int");

            var directoryOperationException = ex as DirectoryOperationException ?? ex.InnerException as DirectoryOperationException;
            if (directoryOperationException?.Response != null)
            {
                diagnostics.AppendLine();
                diagnostics.Append("LDAP ResultCode: ").Append(directoryOperationException.Response.ResultCode);
                diagnostics.AppendLine();
                diagnostics.Append("LDAP ErrorMessage: ").Append(directoryOperationException.Response.ErrorMessage ?? "<empty>");

                if (directoryOperationException.Response is SearchResponse searchResponse)
                {
                    diagnostics.AppendLine();
                    diagnostics.Append("LDAP MatchedDN: ").Append(searchResponse.MatchedDN ?? "<empty>");
                }
            }

            var ldapException = ex as LdapException ?? ex.InnerException as LdapException;
            if (ldapException?.ServerErrorMessage != null)
            {
                diagnostics.AppendLine();
                diagnostics.Append("LDAP ServerErrorMessage: ").Append(ldapException.ServerErrorMessage);
            }

            return diagnostics.ToString();
        }
    }
}
