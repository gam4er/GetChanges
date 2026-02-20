using Spectre.Console;
using System;

namespace GCNet
{
    internal static class AppConsole
    {
        private const ExceptionFormats CompactExceptionFormat =
            ExceptionFormats.ShortenTypes |
            ExceptionFormats.ShortenMethods |
            ExceptionFormats.ShortenPaths |
            ExceptionFormats.ShowLinks;

        public static void Log(string message)
        {
            AnsiConsole.MarkupLine($"[grey]{DateTime.Now:yyyy-MM-dd HH:mm:ss}[/] {Markup.Escape(message)}");
        }

        public static void WriteException(Exception ex, string context)
        {
            Log(context);
            AnsiConsole.Write(new Rule("Compact"));
            AnsiConsole.WriteException(ex, CompactExceptionFormat);
            AnsiConsole.Write(new Rule("Compact"));
        }
    }
}
