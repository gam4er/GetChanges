using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Threading;

namespace GCNet
{
    internal static class GetChanges
    {
        private static int Main(string[] args)
        {
            var app = new CommandApp<RunCommand>();
            return app.Run(args);
        }
    }

    internal sealed class RunCommand : Command<Options>
    {
        protected override int Execute(CommandContext context, Options options, CancellationToken cancellationToken)
        {
            try
            {
                int result = 0;
                AnsiConsole.Status()
                    .AutoRefresh(true)
                    .Spinner(Spinner.Known.Dots)
                    .Start("Starting...", ctx =>
                    {
                        result = new ChangeMonitorApplication().Run(options, ctx);
                    });
                return result;
            }
            catch (Exception ex)
            {
                AppConsole.WriteException(ex, "Fatal application error.");
                return 1;
            }
        }
    }
}
