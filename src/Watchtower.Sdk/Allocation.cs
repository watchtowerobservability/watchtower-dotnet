using System.Diagnostics;
using OpenTelemetry;

namespace Watchtower;

/// <summary>Per-request allocation (APM-007): the bytes a server span's request allocated between its
/// start and its end, set as <c>runtime.alloc.bytes</c> before export. The request's async flow
/// carries a counter in an <see cref="AsyncLocal{T}"/>; its change callback fires whenever that flow
/// starts or stops running on a thread, so each stretch adds that thread's
/// <see cref="GC.GetAllocatedBytesForCurrentThread"/> delta. Requests that await and resume on other
/// threads are therefore counted in full. Off with <c>WT_ALLOC_COUNTER=0</c>.</summary>
public sealed class AllocationProcessor : BaseProcessor<Activity>
{
    public const string Tag = "runtime.alloc.bytes";
    private const string Start = "wt.alloc.start";

    public static bool Enabled => Environment.GetEnvironmentVariable("WT_ALLOC_COUNTER") != "0";

    private sealed class Counter(Counter? parent)
    {
        public readonly Counter? Parent = parent;
        public long Total;
    }

    [ThreadStatic] private static long _enteredAt;

    // Runs on every execution-context switch that changes the value; it must never throw.
    private static readonly AsyncLocal<Counter?> Current = new(e =>
    {
        var now = GC.GetAllocatedBytesForCurrentThread();
        if (e.PreviousValue is { } left) Interlocked.Add(ref left.Total, Math.Max(0, now - _enteredAt));
        if (e.CurrentValue is not null) _enteredAt = now;
    });

    public override void OnStart(Activity a)
    {
        if (a.Kind != ActivityKind.Server) return;
        var c = new Counter(Current.Value);
        a.SetCustomProperty(Start, c);
        Current.Value = c;
    }

    public override void OnEnd(Activity a)
    {
        if (a.GetCustomProperty(Start) is not Counter c) return;
        if (ReferenceEquals(Current.Value, c)) Current.Value = c.Parent; // closes this thread's stretch
        a.SetTag(Tag, Interlocked.Read(ref c.Total));
    }
}
