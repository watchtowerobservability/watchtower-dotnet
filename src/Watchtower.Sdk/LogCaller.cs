using System.Diagnostics;
using OpenTelemetry;
using OpenTelemetry.Logs;

namespace Watchtower;

/// <summary>Stamps <c>code.filepath</c> / <c>code.lineno</c> on log records from the calling frame.
/// Opt-in (<c>WATCHTOWER_LOG_CALLER=1</c>): it walks the stack and reads PDB line info per record.</summary>
public sealed class LogCallerProcessor : BaseProcessor<LogRecord>
{
    public static bool Enabled => System.Environment.GetEnvironmentVariable("WATCHTOWER_LOG_CALLER")?.Trim() == "1";

    private static readonly string[] Skip = { "Microsoft.Extensions.Logging", "OpenTelemetry", "System.", "Watchtower." };

    /// <summary>First frame with a source file outside logging, OpenTelemetry, the BCL and this SDK.</summary>
    public static (string File, int Line)? Find(StackTrace st)
    {
        foreach (var f in st.GetFrames())
        {
            var type = f.GetMethod()?.DeclaringType?.FullName ?? "";
            if (Skip.Any(p => type.StartsWith(p, StringComparison.Ordinal) && !type.StartsWith("Watchtower.Sdk.Tests", StringComparison.Ordinal))) continue;
            if (f.GetFileName() is { Length: > 0 } file) return (file, f.GetFileLineNumber());
        }
        return null;
    }

    // Runs on the logging thread, before the batch exporter reads the record.
    public override void OnEnd(LogRecord data)
    {
        if (Find(new StackTrace(true)) is not { } c) return;
        var attrs = new List<KeyValuePair<string, object?>>(data.Attributes ?? Array.Empty<KeyValuePair<string, object?>>())
        {
            new("code.filepath", c.File), new("code.lineno", c.Line),
        };
        data.Attributes = attrs;
    }
}
