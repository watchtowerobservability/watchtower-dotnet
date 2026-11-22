using System.Text;

namespace Watchtower.Profiling;

/// <summary>
/// Continuous profiler on the runtime's own EventPipe, in process and without native agents:
/// every period it records the SampleProfiler (each managed thread's stack about every
/// millisecond, running or waiting, so a wall-clock profile) with the method rundown, folds the
/// stacks and posts them to the gateway's Pyroscope-compatible <c>/ingest</c> as
/// <c>&lt;service&gt;.wall</c>. Uploads are best effort: failures are counted and dropped.
/// </summary>
public sealed class Profiler : IDisposable
{
    private readonly string _key, _endpoint, _service;
    private readonly SortedDictionary<string, string> _tags;
    private readonly TimeSpan _period;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private readonly CancellationTokenSource _stop = new();
    private Thread? _thread;
    private long _uploaded, _dropped;

    public Profiler(string key, string? endpoint = null, string? service = null, IDictionary<string, string>? tags = null, TimeSpan? period = null)
    {
        if (string.IsNullOrEmpty(key)) throw new ArgumentException("key is required", nameof(key));
        _key = key;
        _endpoint = (endpoint ?? "http://localhost:4318").TrimEnd('/');
        _service = service ?? "app";
        _tags = new SortedDictionary<string, string>(tags ?? new Dictionary<string, string>());
        _period = period is { } p && p >= TimeSpan.FromSeconds(1) ? p : TimeSpan.FromSeconds(15);
    }

    /// <summary>Key, endpoint and service from WT_INGEST_KEY, WT_OTLP_ENDPOINT and WT_SERVICE.</summary>
    public static Profiler FromEnv()
    {
        var tags = new Dictionary<string, string>();
        if (Environment.GetEnvironmentVariable("WT_ENVIRONMENT") is { Length: > 0 } env) tags["env"] = env;
        if (Environment.GetEnvironmentVariable("WT_RELEASE") is { Length: > 0 } rel) tags["version"] = rel;
        return new Profiler(Environment.GetEnvironmentVariable("WT_INGEST_KEY") ?? "",
            Environment.GetEnvironmentVariable("WT_OTLP_ENDPOINT"), Environment.GetEnvironmentVariable("WT_SERVICE"), tags);
    }

    /// <summary>
    /// Also label code after an <c>await</c>, on whichever thread it resumes, and work the span
    /// starts (tasks, timers): the span flows with the ExecutionContext. Off by default because
    /// its overhead (a callback on every context switch under a span) is unmeasured.
    /// </summary>
    public static bool AsyncSpanLabels { get; set; }

    /// <summary>
    /// Labels samples with a span while <paramref name="fn"/> runs (default: the current
    /// <see cref="System.Diagnostics.Activity"/>), so a trace links to its exact profile. By
    /// default this thread only, until <paramref name="fn"/> returns; see
    /// <see cref="AsyncSpanLabels"/> for async code.
    /// </summary>
    public static T WithSpan<T>(Func<T> fn, string? spanId = null, string? traceId = null)
    {
        var a = System.Diagnostics.Activity.Current;
        spanId ??= a?.SpanId.ToHexString();
        traceId ??= a?.TraceId.ToHexString();
        if (spanId == null || traceId == null) return fn();
        var prefix = $"span_id={spanId},trace_id={traceId}\t";
        if (!AsyncSpanLabels)
        {
            var iv = new SpanInterval(OsThread.Id(), System.Diagnostics.Stopwatch.GetTimestamp(), prefix);
            lock (Spans)
                if (Spans.Count < MaxSpans) Spans.Add(iv);
            try { return fn(); }
            finally { iv.End = System.Diagnostics.Stopwatch.GetTimestamp(); }
        }
        var outer = CurrentSpan.Value;
        CurrentSpan.Value = prefix;
        try { return fn(); }
        finally { CurrentSpan.Value = outer; }
    }

    private const int MaxSpans = 100_000;
    private static readonly List<SpanInterval> Spans = new();
    private static readonly AsyncLocal<string?> CurrentSpan = new(OnSpanChange);
    [ThreadStatic] private static SpanInterval? _openSpan;

    /// <summary>
    /// Runs whenever this thread's span changes, by <see cref="WithSpan"/> or by the runtime
    /// switching ExecutionContext (a continuation starts or ends): the thread's open interval ends
    /// and, under a span, the next one starts.
    /// </summary>
    private static void OnSpanChange(AsyncLocalValueChangedArgs<string?> e)
    {
        var now = System.Diagnostics.Stopwatch.GetTimestamp();
        if (_openSpan is { } open)
        {
            open.End = now;
            _openSpan = null;
        }
        if (e.CurrentValue is not { } prefix) return;
        var iv = new SpanInterval(OsThread.Id(), now, prefix);
        lock (Spans)
        {
            if (Spans.Count >= MaxSpans) return;
            Spans.Add(iv);
        }
        _openSpan = iv;
    }

    /// <summary>The intervals a trace ending now can need; intervals that have ended leave the list.</summary>
    private static SpanInterval[] TakeSpans()
    {
        lock (Spans)
        {
            var all = Spans.ToArray();
            Spans.RemoveAll(s => s.End != 0);
            return all;
        }
    }

    public long Uploaded => Interlocked.Read(ref _uploaded);
    public long Dropped => Interlocked.Read(ref _dropped);

    public override string ToString() => $"Profiler{{service={_service}}}";

    private static readonly DiagnosticsIpc.Provider[] Providers =
    {
        new(NetTrace.SampleProvider, 0xF00000000000, 4),
        new(NetTrace.RuntimeProvider, 0x18, 5), // Loader | Jit, verbose: names of methods jitted mid-session
    };

    /// <summary>Records this process for <paramref name="d"/> and returns the raw nettrace.</summary>
    public static byte[] Record(TimeSpan d, CancellationToken ct = default)
    {
        int pid = Environment.ProcessId;
        var (trace, session) = DiagnosticsIpc.Start(pid, Providers);
        using (trace)
        {
            var buf = new MemoryStream();
            var reader = Task.Run(() => trace.CopyTo(buf)); // the stream ends after the stop's rundown
            try
            {
                ct.WaitHandle.WaitOne(d);
            }
            finally
            {
                DiagnosticsIpc.Stop(pid, session);
            }
            if (!reader.Wait(TimeSpan.FromSeconds(30))) throw new IOException("the EventPipe stream did not end");
            return buf.ToArray();
        }
    }

    /// <summary>Folded <c>root;...;leaf</c> stacks of this process over <paramref name="d"/>.</summary>
    public static Dictionary<string, long> Capture(TimeSpan d, CancellationToken ct = default)
    {
        var trace = Record(d, ct);
        return NetTrace.Fold(trace, TakeSpans());
    }

    internal Uri IngestUri(long fromS, long untilS)
    {
        var labels = string.Join(",", _tags.Where(t => t.Value.Length > 0).Select(t => $"{t.Key}={t.Value}"));
        return new Uri($"{_endpoint}/ingest?name={Uri.EscapeDataString($"{_service}.wall{{{labels}}}")}&from={fromS}&until={untilS}" +
            "&format=folded&sampleRate=1000&units=samples&spyName=watchtower-dotnet");
    }

    internal static string Body(Dictionary<string, long> folded)
    {
        var sb = new StringBuilder();
        foreach (var (k, n) in folded) sb.Append(k).Append(' ').Append(n).Append('\n');
        return sb.ToString();
    }

    internal void Upload(Dictionary<string, long> folded, long fromS, long untilS)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, IngestUri(fromS, untilS)) { Content = new StringContent(Body(folded), Encoding.UTF8, "text/plain") };
            req.Headers.Add("Authorization", "Bearer " + _key);
            using var resp = _http.Send(req);
            Interlocked.Increment(ref resp.IsSuccessStatusCode ? ref _uploaded : ref _dropped);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
        {
            Interlocked.Increment(ref _dropped);
        }
    }

    public Profiler Start()
    {
        lock (_stop)
        {
            if (_thread != null) return this;
            _thread = new Thread(Run) { IsBackground = true, Name = "watchtower-profiler" };
            _thread.Start();
            return this;
        }
    }

    private void Run()
    {
        while (!_stop.IsCancellationRequested)
        {
            long from = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            try
            {
                var folded = Capture(_period, _stop.Token);
                if (folded.Count > 0) Upload(folded, from, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            }
            catch (Exception e) when (e is IOException or InvalidDataException or System.Net.Sockets.SocketException or UnauthorizedAccessException)
            {
                Interlocked.Increment(ref _dropped);
                _stop.Token.WaitHandle.WaitOne(_period); // the diagnostics server is off or busy: retry later
            }
        }
    }

    public void Dispose()
    {
        _stop.Cancel();
        _thread?.Join(TimeSpan.FromSeconds(35));
        _http.Dispose();
    }
}
