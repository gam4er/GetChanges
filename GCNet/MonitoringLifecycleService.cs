using System;
using System.Threading;
using System.Threading.Tasks;

namespace GCNet
{
    internal interface IMonitoringLifecycleService : IDisposable
    {
        CancellationToken Token { get; }
        void WaitForStopSignal();
        void RequestStop();
        void WaitForTask(Task task, TimeSpan timeout, string errorMessage);
        void WaitForTasks(Task[] tasks, TimeSpan timeout, string errorMessage);
    }

    internal sealed class MonitoringLifecycleService : IMonitoringLifecycleService
    {
        private readonly CancellationTokenSource _tokenSource = new CancellationTokenSource();
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private int _stopRequested;

        public CancellationToken Token => _tokenSource.Token;

        public void WaitForStopSignal()
        {
            Console.CancelKeyPress += OnCancelKeyPress;
            AppConsole.Log("Monitoring starting. Press ENTER or CTRL+C to stop.");

            using (var registration = _tokenSource.Token.Register(() => _stopSignal.Set()))
            {
                _ = Task.Run(() =>
                {
                    try
                    {
                        Console.ReadLine();
                        AppConsole.Log("stop-signal: ENTER pressed.");
                        _stopSignal.Set();
                    }
                    catch (Exception ex)
                    {
                        AppConsole.Log("stop-signal: unable to read console input. " + ex.Message);
                        _stopSignal.Set();
                    }
                });

                _stopSignal.Wait();
            }

            Console.CancelKeyPress -= OnCancelKeyPress;
        }

        public void RequestStop()
        {
            if (Interlocked.Exchange(ref _stopRequested, 1) == 1)
            {
                return;
            }

            AppConsole.Log("Stopping monitoring and completing pipeline...");
            _tokenSource.Cancel();
            _stopSignal.Set();
        }

        public void WaitForTask(Task task, TimeSpan timeout, string errorMessage)
        {
            try
            {
                task.Wait(timeout);
            }
            catch (Exception ex)
            {
                AppConsole.WriteException(ex, errorMessage);
            }
        }

        public void WaitForTasks(Task[] tasks, TimeSpan timeout, string errorMessage)
        {
            try
            {
                Task.WaitAll(tasks, timeout);
            }
            catch (Exception ex)
            {
                AppConsole.WriteException(ex, errorMessage);
            }
        }

        public void Dispose()
        {
            Console.CancelKeyPress -= OnCancelKeyPress;
            _stopSignal.Dispose();
            _tokenSource.Dispose();
        }

        private void OnCancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            AppConsole.Log("stop-signal: CTRL+C pressed.");
            RequestStop();
        }
    }
}
