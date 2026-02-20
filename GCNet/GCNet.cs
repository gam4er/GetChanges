using CommandLine;
using System;

namespace GCNet
{
    internal static class GCNet
    {
        private static int Main(string[] args)
        {
            try
            {
                return Parser.Default
                    .ParseArguments<Options>(args)
                    .MapResult(
                        opts => new ChangeMonitorApplication().Run(opts),
                        _ => 1);
            }
            catch (Exception ex)
            {
                AppConsole.WriteException(ex, "Fatal application error.");
                return 1;
            }
        }
    }
}
