using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Watchtower.Probes;
using Xunit;

namespace Watchtower.Sdk.Tests;

public class ProbeShop
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public int Checkout(Trap user, int total) => total + user.GetHashCode() * 0;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public string Pay(int total) => total > 0 ? Activity.Current?.OperationName ?? "" : throw new InvalidOperationException("declined");

    [MethodImpl(MethodImplOptions.NoInlining)]
    public int Tag(Trap user, int total) => total;
}

// A value whose members must never run during a snapshot or a condition.
public class Trap
{
    private readonly int _id = 7;
    public int Id => throw new InvalidOperationException("getter ran");
    public override string ToString() => throw new InvalidOperationException("ToString ran");
    public override int GetHashCode() => _id - 7;
    public override bool Equals(object? o) => throw new InvalidOperationException("Equals ran");
}

public class ProbesTests
{
    private static JsonElement Def(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Fact]
    public void FunctionProbeSnapshotsArgsByFieldsAndHonoursRateLimit()
    {
        var events = new List<Dictionary<string, string>>();
        var s = new ProbeSet("http://127.0.0.1:1", "k", "s", emit: (_, a) => events.Add(a), nowMs: () => 1000);
        s.Set(new[] { Def("""{"id":"p1","location":{"function":"Watchtower.Sdk.Tests.ProbeShop#Checkout"},"condition":"total > 10","max_rate_per_min":2}""") });
        var shop = new ProbeShop();
        for (var i = 0; i < 3; i++) shop.Checkout(new Trap(), 50);
        shop.Checkout(new Trap(), 5); // condition false
        s.Set(Array.Empty<JsonElement>());
        shop.Checkout(new Trap(), 50); // unpatched
        Assert.True(events.Count == 2, $"events={events.Count} last={ProbeSet.LastError}");
        Assert.Equal("p1", events[0]["probe.id"]);
        Assert.Equal("50", events[0]["code.snapshot.total"]);
        Assert.Equal("7", events[0]["code.snapshot.user._id"]);
    }

    [Fact]
    public void RefusesFrameworkTargetsAndExpiredProbes()
    {
        var events = new List<Dictionary<string, string>>();
        var s = new ProbeSet("http://127.0.0.1:1", "k", "s", emit: (_, a) => events.Add(a), nowMs: () => 10_000_000, patch: false);
        s.Set(new[] { Def("""{"id":"e","expires_at":5}"""), Def("""{"id":"ok"}""") });
        s.Hit("e", "f", "x", 1, new Dictionary<string, object?>());
        s.Hit("ok", "f", "x", 1, new Dictionary<string, object?> { ["a"] = 1L });
        Assert.Single(events);
        Assert.Equal("1", events[0]["code.snapshot.a"]);
    }

    [Fact]
    public void ConditionSubsetRefusesCalls()
    {
        Assert.ThrowsAny<Exception>(() => Condition.Compile("Exec(\"x\")"));
        var ok = Condition.Compile("user._id == 7 && name in ['a', 'b']");
        Assert.True(ok(new Dictionary<string, object?> { ["user"] = ProbeSet.Plain(new Trap(), 1), ["name"] = "a" }));
    }

    [Fact]
    public void CaptureBounds()
    {
        var deep = new Dictionary<string, object?> { ["b"] = new Dictionary<string, object?> { ["c"] = new Dictionary<string, object?> { ["d"] = 1L } } };
        var out_ = ProbeSet.Capture(new Dictionary<string, object?> { ["a"] = deep, ["big"] = new string('x', 5000) }, 2, 2000);
        Assert.Equal("[depth limit]", out_["a.b.c"]);
        Assert.Equal(1024, out_["big"].Length);
    }

    [Fact]
    public void SpanProbeWrapsTheCallAndMarksThrows()
    {
        var stopped = new List<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = src => src.Name == "Watchtower",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = a => { if ((a.GetTagItem("probe.id") as string) == "sp") lock (stopped) stopped.Add(a); },
        };
        ActivitySource.AddActivityListener(listener);
        var s = new ProbeSet("http://127.0.0.1:1", "k", "s", emit: (_, _) => { }, nowMs: () => 1000);
        s.Set(new[] { Def("""{"id":"sp","kind":"span","location":{"function":"Watchtower.Sdk.Tests.ProbeShop#Pay"},"condition":"total != 7"}""") });
        var shop = new ProbeShop();
        Assert.Equal("probe Pay", shop.Pay(5)); // current inside the call
        Assert.Throws<InvalidOperationException>(() => shop.Pay(-1));
        shop.Pay(7); // condition false
        s.Set(Array.Empty<JsonElement>());
        Assert.Equal(2, stopped.Count);
        Assert.Equal(ActivityStatusCode.Unset, stopped[0].Status);
        Assert.Equal("Watchtower.Sdk.Tests.ProbeShop#Pay", stopped[0].GetTagItem("code.function"));
        Assert.Equal(ActivityStatusCode.Error, stopped[1].Status);
    }

    [Fact]
    public void SpanDecorationTagsTheCurrentActivityAndSkipsWt()
    {
        var s = new ProbeSet("http://127.0.0.1:1", "k", "s", emit: (_, _) => { }, nowMs: () => 1000);
        s.Set(new[] { Def("""{"id":"d","kind":"span_decoration","location":{"function":"Watchtower.Sdk.Tests.ProbeShop#Tag"},"capture":{"tags":[{"name":"order.total","value":"t={total} u={user._id} x={nope}"},{"name":"wt.tenant","value":"evil"}]}}""") });
        var parent = new Activity("request").Start();
        try { new ProbeShop().Tag(new Trap(), 42); }
        finally { parent.Stop(); s.Set(Array.Empty<JsonElement>()); }
        Assert.Equal("t=42 u=7 x=", parent.GetTagItem("order.total"));
        Assert.Null(parent.GetTagItem("wt.tenant"));
        Assert.Equal("a.b=3", ProbeSet.Render("a.b={a.b}", new Dictionary<string, object?> { ["a"] = new Dictionary<string, object?> { ["b"] = 3L } }));
    }
}
