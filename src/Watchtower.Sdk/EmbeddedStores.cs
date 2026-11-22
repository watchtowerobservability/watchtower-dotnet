using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Caching.Memory;

namespace Watchtower;

/// <summary>
/// wt.embedded.* health metrics for in-process and embedded stores (MemoryCache, SQLite via
/// Microsoft.Data.Sqlite, LiteDB, any file-backed store), on the "Watchtower" meter that
/// AddWatchtower already listens to. Keys and values are never recorded.
/// </summary>
public static class EmbeddedStores
{
    public static readonly string[] Gauges =
    {
        "file.size", "wal.size", "map.size", "map.used", "memory.used", "cache.size", "keys",
        "compaction.pending", "transactions.open", "free_pages", "levels.files", "snapshots.open",
        "iterators.open", "readers",
    };

    public static readonly string[] Counters =
    {
        "cache.hits", "cache.misses", "cache.evictions", "cache.rejections", "lock.waits", "lock.wait_time",
        "compactions", "compaction.duration", "flushes", "transactions", "bytes.written", "bytes.read",
    };

    private sealed record Source(KeyValuePair<string, object?>[] Tags, Func<IReadOnlyDictionary<string, long>> Read);

    private static readonly ConcurrentDictionary<Source, byte> Sources = new();
    private static readonly Meter Meter = new(Watchtower.SourceName);

    static EmbeddedStores()
    {
        foreach (var g in Gauges)
        {
            var name = "wt.embedded." + g;
            Meter.CreateObservableGauge(name, () => Observe(name));
        }
        foreach (var c in Counters)
        {
            var name = "wt.embedded." + c;
            Meter.CreateObservableCounter(name, () => Observe(name));
        }
    }

    // Reads every source once per instrument; sources are cheap stat calls.
    private static IEnumerable<Measurement<long>> Observe(string name)
    {
        foreach (var s in Sources.Keys)
        {
            IReadOnlyDictionary<string, long> r;
            try { r = s.Read(); }
            catch { continue; } // a disposed store reports nothing
            if (r.TryGetValue(name, out var v) && v >= 0) yield return new Measurement<long>(v, s.Tags);
        }
    }

    /// <summary>Report <paramref name="read"/> (metric name to value) tagged db.system.name and db.namespace until disposed.</summary>
    public static IDisposable Observe(string system, string ns, Func<IReadOnlyDictionary<string, long>> read)
    {
        var s = new Source(new KeyValuePair<string, object?>[] { new("db.system.name", system), new("db.namespace", ns) }, read);
        Sources[s] = 0;
        return new Unregister(() => Sources.TryRemove(s, out _));
    }

    private sealed class Unregister(Action a) : IDisposable
    {
        public void Dispose() => a();
    }

    /// <summary>Entries, estimated size, hits and misses of a MemoryCache created with TrackStatistics = true.</summary>
    public static IDisposable ObserveMemoryCache(MemoryCache cache, string name) => Observe("memorycache", name, () =>
    {
        var st = cache.GetCurrentStatistics();
        if (st is null) return new Dictionary<string, long>();
        var r = new Dictionary<string, long>
        {
            ["wt.embedded.keys"] = st.CurrentEntryCount,
            ["wt.embedded.cache.hits"] = st.TotalHits,
            ["wt.embedded.cache.misses"] = st.TotalMisses,
        };
        if (st.CurrentEstimatedSize is long size) r["wt.embedded.cache.size"] = size;
        return r;
    });

    /// <summary>File and WAL size of a file-backed store: SQLite (wal = path + "-wal"), LiteDB (wal = path minus ".db" + "-log.db"), DuckDB (path + ".wal").</summary>
    public static IDisposable ObserveFiles(string system, string path, string? walPath = null) => Observe(system, path, () =>
    {
        var r = new Dictionary<string, long>();
        if (File.Exists(path)) r["wt.embedded.file.size"] = new FileInfo(path).Length;
        if (walPath is not null && File.Exists(walPath)) r["wt.embedded.wal.size"] = new FileInfo(walPath).Length;
        return r;
    });
}
