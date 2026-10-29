using System.Diagnostics;
using OpenTelemetry.Trace;

namespace Watchtower;

/// <summary>Records exceptions as OTel "exception" span events so errors share a trace id with everything else.</summary>
public static class ErrorCapture
{
    private static readonly ActivitySource Source = new(Watchtower.SourceName);

    /// <summary>Attaches the exception to the current span (or a new "exception" span) and returns the trace id,
    /// or null when nothing is listening. Extra tags lose their wt.* keys.</summary>
    public static string? Capture(Exception ex, IReadOnlyDictionary<string, object?>? tags = null, bool escaped = false)
    {
        using var own = Activity.Current is null ? Source.StartActivity("exception") : null;
        var a = Activity.Current;
        if (a is null) return null;
        var t = new ActivityTagsCollection
        {
            ["exception.type"] = ex.GetType().FullName,
            ["exception.message"] = ex.Message,
            ["exception.stacktrace"] = ex.ToString(),
            ["exception.escaped"] = escaped,
        };
        if (tags is not null)
            foreach (var (k, v) in Redaction.DropReserved(tags)) t[k] = v;
        a.AddEvent(new ActivityEvent("exception", tags: t));
        a.SetStatus(ActivityStatusCode.Error, ex.Message);
        return a.TraceId.ToString();
    }

    /// <summary>Hooks AppDomain unhandled and TaskScheduler unobserved exceptions. Dispose to unhook.
    /// Pass the provider so a terminating crash flushes first.</summary>
    public static IDisposable Install(TracerProvider? provider = null)
    {
        UnhandledExceptionEventHandler onCrash = (_, e) =>
        {
            if (e.ExceptionObject is Exception ex) Capture(ex, escaped: true);
            provider?.ForceFlush(2000);
        };
        EventHandler<UnobservedTaskExceptionEventArgs> onTask = (_, e) => Capture(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += onCrash;
        TaskScheduler.UnobservedTaskException += onTask;
        return new Unhook(() =>
        {
            AppDomain.CurrentDomain.UnhandledException -= onCrash;
            TaskScheduler.UnobservedTaskException -= onTask;
        });
    }

    private sealed class Unhook(Action undo) : IDisposable
    {
        public void Dispose() => undo();
    }
}
