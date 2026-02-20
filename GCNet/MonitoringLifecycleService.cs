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

        public CancellationToken Token => _tokenSource.Token;

        public void WaitForStopSignal()
        {
            AppConsole.Log("Monitoring starting. Press ENTER to stop.");
            Console.ReadLine();
        }

        public void RequestStop()
        {
            AppConsole.Log("Stopping monitoring and completing pipeline...");
            _tokenSource.Cancel();
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
            _tokenSource.Dispose();
        }
    }
}
