using System.Diagnostics.Metrics;
using Microsoft.Extensions.Caching.Memory;
using Watchtower;
using Xunit;

public class EmbeddedStoresTests
{
    private static Dictionary<string, long> Collect(string ns)
    {
        var got = new Dictionary<string, long>();
        using var l = new MeterListener();
        l.InstrumentPublished = (i, ml) => { if (i.Meter.Name == "Watchtower" && i.Name.StartsWith("wt.embedded.")) ml.EnableMeasurementEvents(i); };
        l.SetMeasurementEventCallback<long>((i, v, tags, _) =>
        {
            foreach (var t in tags) if (t.Key == "db.namespace" && (string?)t.Value == ns) got[i.Name] = v;
        });
        l.Start();
        l.RecordObservableInstruments();
        return got;
    }

    [Fact]
    public void MemoryCacheHitsMissesAndEntries()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions { TrackStatistics = true });
        cache.Set("a", 1);
        cache.TryGetValue("a", out _);
        cache.TryGetValue("b", out _);
        using var h = EmbeddedStores.ObserveMemoryCache(cache, "sessions");
        var got = Collect("sessions");
        Assert.Equal(1, got["wt.embedded.cache.hits"]);
        Assert.Equal(1, got["wt.embedded.cache.misses"]);
        Assert.Equal(1, got["wt.embedded.keys"]);
    }

    [Fact]
    public void FilesAndUnregister()
    {
        var path = Path.GetTempFileName();
        File.WriteAllBytes(path, new byte[512]);
        var h = EmbeddedStores.ObserveFiles("sqlite", path, path + "-wal");
        Assert.Equal(512, Collect(path)["wt.embedded.file.size"]);
        Assert.False(Collect(path).ContainsKey("wt.embedded.wal.size"));
        h.Dispose();
        Assert.Empty(Collect(path));
        File.Delete(path);
    }
}
