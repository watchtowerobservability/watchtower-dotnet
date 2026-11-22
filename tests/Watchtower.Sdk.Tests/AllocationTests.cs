using System.Diagnostics;
using Watchtower;
using Xunit;

public class AllocationTests
{
    private static object? _sink; // keeps the test allocation alive

    [Fact]
    public void ServerActivityGetsItsThreadsAllocation()
    {
        using var src = new ActivitySource("alloc-test");
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == "alloc-test",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
        };
        ActivitySource.AddActivityListener(listener);
        var p = new AllocationProcessor();

        using var server = src.StartActivity("GET /orders", ActivityKind.Server)!;
        p.OnStart(server);
        _sink = new byte[256 * 1024];
        p.OnEnd(server);
        Assert.True((long)server.GetTagItem(AllocationProcessor.Tag)! >= 256 * 1024);

        using var inner = src.StartActivity("internal", ActivityKind.Internal)!;
        p.OnStart(inner);
        p.OnEnd(inner);
        Assert.Null(inner.GetTagItem(AllocationProcessor.Tag));
    }

    [Fact]
    public async Task RequestThatResumesOnOtherThreadsIsCountedInFull()
    {
        using var src = new ActivitySource("alloc-async");
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == "alloc-async",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
        };
        ActivitySource.AddActivityListener(listener);
        var p = new AllocationProcessor();

        using var server = src.StartActivity("POST /orders", ActivityKind.Server)!;
        p.OnStart(server);
        // each await resumes on a pool thread; the allocations happen on others still
        await Task.Run(() => { _sink = new byte[512 * 1024]; }).ConfigureAwait(false);
        await Task.Run(() => { _sink = new byte[512 * 1024]; }).ConfigureAwait(false);
        p.OnEnd(server);
        Assert.True((long)server.GetTagItem(AllocationProcessor.Tag)! >= 1024 * 1024);
    }
}
