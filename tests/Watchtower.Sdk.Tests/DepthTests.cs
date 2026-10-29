using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry;
using OpenTelemetry.Trace;
using Watchtower;
using Xunit;

public class DepthTests
{
    private sealed class FakeExporter : BaseExporter<Activity>
    {
        public bool Fail = true;
        public List<int> Sizes = new();

        public override ExportResult Export(in Batch<Activity> batch)
        {
            Sizes.Add((int)batch.Count);
            return Fail ? ExportResult.Failure : ExportResult.Success;
        }
    }

    [Fact]
    public void FailedExportIsRetriedWithNextBatch()
    {
        using var src = new ActivitySource("t.buf");
        using var l = new ActivityListener
        {
            ShouldListenTo = s => s.Name == "t.buf",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
        };
        ActivitySource.AddActivityListener(l);
        var inner = new FakeExporter();
        var ex = new BufferingExporter(inner, new OfflineBuffer<Activity>(10));

        var a1 = src.StartActivity("a1")!; a1.Stop();
        Assert.Equal(ExportResult.Success, ex.Export(new Batch<Activity>(new[] { a1 }, 1)));
        inner.Fail = false;
        var a2 = src.StartActivity("a2")!; a2.Stop();
        ex.Export(new Batch<Activity>(new[] { a2 }, 1));

        Assert.Equal(new[] { 1, 2 }, inner.Sizes);
    }

    [Fact]
    public void CaptureRecordsExceptionEventWithTraceId()
    {
        using var l = new ActivityListener
        {
            ShouldListenTo = s => s.Name == Watchtower.Watchtower.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
        };
        ActivitySource.AddActivityListener(l);
        var tid = ErrorCapture.Capture(new InvalidOperationException("boom"),
            new Dictionary<string, object?> { ["wt.tenant"] = "x", ["k"] = "v" });
        Assert.NotNull(tid);
        Assert.Equal(32, tid!.Length);
    }

    [Fact]
    public void CaptureWithoutListenerReturnsNull() =>
        Assert.Null(ErrorCapture.Capture(new Exception("nobody listening")));

    [Fact]
    public void InstallHooksAreRemovable()
    {
        using var h = ErrorCapture.Install();
        h.Dispose();
    }

    [Fact]
    public void FromEnvReadsAllNamesAndAlias()
    {
        var names = new[] { "WT_SERVICE", "WT_OTLP_ENDPOINT", "WT_ENDPOINT", "WT_ENVIRONMENT", "WT_RELEASE", "WT_INGEST_KEY" };
        var old = names.ToDictionary(n => n, Environment.GetEnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable("WT_SERVICE", "svc");
            Environment.SetEnvironmentVariable("WT_ENDPOINT", "http://old:1");
            Environment.SetEnvironmentVariable("WT_ENVIRONMENT", "prod");
            Environment.SetEnvironmentVariable("WT_RELEASE", "1.2.3");
            var c = Config.FromEnv();
            Assert.Equal("http://old:1", c.Endpoint);
            Environment.SetEnvironmentVariable("WT_OTLP_ENDPOINT", "http://new:2");
            c = Config.FromEnv();
            Assert.Equal("http://new:2", c.Endpoint);
            var a = c.ResourceAttributes();
            Assert.Equal("svc", a["service.name"]);
            Assert.Equal("prod", a["deployment.environment"]);
            Assert.Equal("1.2.3", a["service.version"]);
        }
        finally
        {
            foreach (var (n, v) in old) Environment.SetEnvironmentVariable(n, v);
        }
    }

    [Fact]
    public void AddWatchtowerBuildsTracerProvider()
    {
        var sc = new ServiceCollection();
        sc.AddLogging();
        sc.AddWatchtower(new Config("svc", key: "wtk_example_not_a_real_key"));
        using var sp = sc.BuildServiceProvider();
        Assert.NotNull(sp.GetService<TracerProvider>());
    }
}
