using System.Diagnostics;
using OpenTelemetry;

namespace Watchtower;

/// <summary>Wraps an exporter: a failed or throwing export parks its spans in the
/// <see cref="OfflineBuffer{T}"/>; the next export retries them ahead of new spans.</summary>
public sealed class BufferingExporter : BaseExporter<Activity>
{
    private readonly BaseExporter<Activity> _inner;
    private readonly OfflineBuffer<Activity> _buffer;

    public BufferingExporter(BaseExporter<Activity> inner, OfflineBuffer<Activity> buffer)
    {
        _inner = inner;
        _buffer = buffer;
    }

    public override ExportResult Export(in Batch<Activity> batch)
    {
        var items = _buffer.Drain();
        foreach (var a in batch) items.Add(a);
        if (items.Count == 0) return ExportResult.Success;
        var arr = items.ToArray();
        var ok = false;
        try { ok = _inner.Export(new Batch<Activity>(arr, arr.Length)) == ExportResult.Success; }
        catch { /* exporter faults must never reach the app; spans are re-buffered below */ }
        if (!ok) foreach (var a in arr) _buffer.Push(a);
        // Success either way: the buffer owns retries, the processor must not drop or throw.
        return ExportResult.Success;
    }

    protected override bool OnShutdown(int timeoutMilliseconds) => _inner.Shutdown(timeoutMilliseconds);

    protected override void Dispose(bool disposing)
    {
        if (disposing) _inner.Dispose();
        base.Dispose(disposing);
    }
}
