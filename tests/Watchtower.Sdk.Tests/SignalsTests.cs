using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Watchtower;
using Xunit;

/// <summary>Logs and metrics reach a fake OTLP/HTTP endpoint; log records carry the active trace and span ids.</summary>
public sealed class SignalsTests : IDisposable
{
    private const string Key = "wtk_example_not_a_real_key"; // fake
    private readonly HttpListener _http = new();
    private readonly ConcurrentQueue<(string Path, string? Auth, byte[] Body)> _got = new();
    private readonly string _url;

    public SignalsTests()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        _url = $"http://localhost:{port}"; // a localhost prefix needs no URL ACL on Windows
        _http.Prefixes.Add(_url + "/");
        _http.Start();
        _ = Task.Run(async () =>
        {
            while (_http.IsListening)
            {
                HttpListenerContext ctx;
                try { ctx = await _http.GetContextAsync(); } catch { return; }
                using var ms = new MemoryStream();
                await ctx.Request.InputStream.CopyToAsync(ms);
                _got.Enqueue((ctx.Request.Url!.AbsolutePath, ctx.Request.Headers["Authorization"], ms.ToArray()));
                ctx.Response.StatusCode = 200;
                ctx.Response.Close();
            }
        });
    }

    public void Dispose() => _http.Close();

    private byte[] Bodies(string path) => _got.Where(g => g.Path == path).SelectMany(g => g.Body).ToArray();

    private static bool Contains(byte[] hay, byte[] needle) =>
        Enumerable.Range(0, Math.Max(0, hay.Length - needle.Length + 1)).Any(i => hay.AsSpan(i, needle.Length).SequenceEqual(needle));

    private static byte[] Hex(string h) => Convert.FromHexString(h);

    [Fact]
    public void ILoggerRecordsCarryTraceAndSpanIds()
    {
        var cfg = new Config("svc", _url, Key);
        using var tp = Sdk.CreateTracerProviderBuilder().AddSource("t.signals").Build();
        using var src = new ActivitySource("t.signals");
        string traceId, spanId;
        using (var factory = Signals.CreateLoggerFactory(cfg))
        {
            var log = factory.CreateLogger("signals");
            using (var a = src.StartActivity("op")!)
            {
                traceId = a.TraceId.ToHexString();
                spanId = a.SpanId.ToHexString();
                log.LogInformation("hello {Who}", "logs");
            }
        } // disposing the factory flushes the batch
        var body = Bodies("/v1/logs");
        Assert.True(Contains(body, Encoding.UTF8.GetBytes("hello logs")));
        Assert.True(Contains(body, Hex(traceId)), "log record carries the trace id");
        Assert.True(Contains(body, Hex(spanId)), "log record carries the span id");
        Assert.All(_got, g => Assert.Equal($"Bearer {Key}", g.Auth));
    }

    [Fact]
    public void MetricsExportToTheMetricsPathWithDeltaByDefault()
    {
        Assert.Equal(MetricReaderTemporalityPreference.Delta, Signals.Temporality());
        var cfg = new Config("svc", _url, Key);
        using var meter = new Meter("t.metrics");
        using (var mp = Sdk.CreateMeterProviderBuilder().AddWatchtower(cfg, "t.metrics").Build())
        {
            meter.CreateCounter<long>("jobs.done").Add(3);
            Assert.True(mp.ForceFlush(10_000));
        }
        Assert.True(Contains(Bodies("/v1/metrics"), Encoding.UTF8.GetBytes("jobs.done")));
        Assert.Contains(_got, g => g.Path == "/v1/metrics" && g.Auth == $"Bearer {Key}");
    }

    [Fact]
    public void SwitchesAndSpoolFromEnv()
    {
        System.Environment.SetEnvironmentVariable("WATCHTOWER_METRICS", "off");
        try { Assert.False(Signals.MetricsOn); Assert.Null(Signals.InitMetrics(new Config("svc"))); }
        finally { System.Environment.SetEnvironmentVariable("WATCHTOWER_METRICS", null); }
        Assert.True(Signals.MetricsOn);
        var dir = Path.Combine(Path.GetTempPath(), "wt-spool-" + Guid.NewGuid().ToString("N"));
        System.Environment.SetEnvironmentVariable("WT_SPOOL_DIR", dir);
        try
        {
            Signals.UseSpoolFromEnv();
            Assert.Equal("disk", System.Environment.GetEnvironmentVariable("OTEL_DOTNET_EXPERIMENTAL_OTLP_RETRY"));
            Assert.Equal(dir, System.Environment.GetEnvironmentVariable("OTEL_DOTNET_EXPERIMENTAL_OTLP_DISK_RETRY_DIRECTORY_PATH"));
        }
        finally
        {
            foreach (var k in new[] { "WT_SPOOL_DIR", "OTEL_DOTNET_EXPERIMENTAL_OTLP_RETRY", "OTEL_DOTNET_EXPERIMENTAL_OTLP_DISK_RETRY_DIRECTORY_PATH" })
                System.Environment.SetEnvironmentVariable(k, null);
        }
    }
}
