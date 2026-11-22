using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using OpenTelemetry.Trace;

namespace Watchtower;

/// <summary>Remote sampling (S5): polls GET /v1/sampling (ETag) and applies the project's head
/// rules in the process. The decision uses fnv64a of the trace id like the gateway, so every
/// service agrees on a trace. A failed poll keeps the last good config (initially: keep
/// everything). Spans dropped here never reach the gateway, so its exact request counts see only
/// what is kept. Wrap it in <see cref="ParentBasedSampler"/>.</summary>
public sealed class RemoteSampler : Sampler, IDisposable
{
    private volatile Cfg? _cfg; // boxed: a JsonElement struct cannot be volatile and may tear
    private sealed record Cfg(JsonElement E);
    private string _etag = "";
    private readonly string _endpoint, _key, _service, _env;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly CancellationTokenSource _stop = new();

    public RemoteSampler(string endpoint, string? key, string service, string? env, TimeSpan interval)
    {
        (_endpoint, _key, _service, _env) = (endpoint.TrimEnd('/'), key ?? "", service, env ?? "");
        Description = "WatchtowerRemoteSampler";
        var every = interval < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(30) : interval;
        _ = Task.Run(async () =>
        {
            using var t = new PeriodicTimer(every);
            await PollAsync();
            while (await t.WaitForNextTickAsync(_stop.Token).ConfigureAwait(false)) await PollAsync();
        }, _stop.Token);
    }

    /// <summary>One poll; any failure or a 304 keeps the current config.</summary>
    public async Task PollAsync()
    {
        try
        {
            var url = $"{_endpoint}/v1/sampling?service={Uri.EscapeDataString(_service)}" + (_env.Length > 0 ? $"&env={Uri.EscapeDataString(_env)}" : "");
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _key);
            if (_etag.Length > 0) req.Headers.TryAddWithoutValidation("If-None-Match", _etag);
            using var res = await _http.SendAsync(req).ConfigureAwait(false);
            if (!res.IsSuccessStatusCode) return;
            var body = await res.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (body.Length > 1 << 20) return;
            _cfg = new Cfg(JsonDocument.Parse(body).RootElement.Clone());
            _etag = res.Headers.ETag?.ToString() ?? "";
        }
        catch (Exception)
        {
            // keep the last good config
        }
    }

    internal void SetConfig(string json) => _cfg = new Cfg(JsonDocument.Parse(json).RootElement.Clone());

    /// <summary>fnv64a over the 16 trace-id bytes, as a fraction of 2^64.</summary>
    internal static double TraceFraction(ReadOnlySpan<byte> id)
    {
        ulong h = 0xcbf29ce484222325UL;
        foreach (var b in id) h = (h ^ b) * 0x100000001b3UL;
        return h / 18446744073709551616.0;
    }

    private static double Clamp(JsonElement e) => e.ValueKind == JsonValueKind.Number ? Math.Min(1, Math.Max(0, e.GetDouble())) : 1;

    private static bool Str(JsonElement m, string name, out string v)
    {
        v = "";
        if (m.TryGetProperty(name, out var e) && e.ValueKind == JsonValueKind.String && e.GetString() is { Length: > 0 } s) { v = s; return true; }
        return false;
    }

    /// <summary>Keep ratio for a root span (1 keeps); the first matching ratio or drop rule wins.</summary>
    internal static double RatioFor(JsonElement c, string service, string env, string name, IEnumerable<KeyValuePair<string, object?>>? tags)
    {
        if (c.ValueKind != JsonValueKind.Object) return 1;
        if (Str(c, "strategyType", out var st) && st == "PROBABILISTIC" && c.TryGetProperty("probabilisticSampling", out var p)
            && p.TryGetProperty("samplingRate", out var rate)) return Clamp(rate);
        if (!c.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array) return 1;
        foreach (var r in rules.EnumerateArray())
        {
            if (!r.TryGetProperty("match", out var m)) continue;
            if (r.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.False) continue;
            if ((m.TryGetProperty("min_duration_ms", out var md) && md.ValueKind != JsonValueKind.Null) || Str(m, "status", out _)) continue; // gateway decides
            if (Str(m, "service", out var s) && s != service) continue;
            if (Str(m, "env", out var e) && e != env) continue;
            if (m.TryGetProperty("span_name_prefix", out var pf) && pf.ValueKind == JsonValueKind.String && !name.StartsWith(pf.GetString()!, StringComparison.Ordinal)) continue;
            if (Str(m, "span_name_glob", out var g) && !Regex.IsMatch(name, "^" + Regex.Escape(g).Replace("\\*", ".*").Replace("\\?", ".") + "$", RegexOptions.Singleline)) continue;
            if (Str(m, "span_name_regex", out var rx))
            {
                try { if (!Regex.IsMatch(name, rx)) continue; } catch (ArgumentException) { continue; }
            }
            if (m.TryGetProperty("attrs", out var want) && want.ValueKind == JsonValueKind.Object
                && want.EnumerateObject().Any(w => !(tags ?? []).Any(t => t.Key == w.Name && Convert.ToString(t.Value) == w.Value.GetString()))) continue;
            if (r.TryGetProperty("action", out var a) && Str(a, "kind", out var k))
            {
                if (k == "drop") return 0;
                if (k == "ratio" && a.TryGetProperty("ratio", out var ra)) return Clamp(ra);
            }
            return 1;
        }
        return 1;
    }

    public override SamplingResult ShouldSample(in SamplingParameters p)
    {
        var r = RatioFor(_cfg?.E ?? default, _service, _env, p.Name, p.Tags);
        Span<byte> id = stackalloc byte[16];
        p.TraceId.CopyTo(id);
        return r >= 1 || (r > 0 && TraceFraction(id) < r)
            ? new SamplingResult(SamplingDecision.RecordAndSample) : new SamplingResult(SamplingDecision.Drop);
    }

    public void Dispose() { _stop.Cancel(); _http.Dispose(); }
}

/// <summary>Code origin (L2): stamps code.filepath, code.lineno and code.function with the
/// application frame that started an activity. Opt-in (WT_CODE_ORIGIN=1) because it walks the
/// stack per span; file and line need the assembly's debug symbols.</summary>
public sealed class CodeOriginProcessor : OpenTelemetry.BaseProcessor<Activity>
{
    private static readonly string[] Skip = ["System.", "Microsoft.", "OpenTelemetry", "Watchtower."];

    internal static bool Skipped(string? ns) => ns is null || Skip.Any(s => ns.StartsWith(s, StringComparison.Ordinal));

    public override void OnStart(Activity a)
    {
        if (a.GetTagItem("code.filepath") is not null) return;
        foreach (var f in new StackTrace(1, true).GetFrames())
        {
            var m = f.GetMethod();
            if (m?.DeclaringType is not { } t || Skipped(t.FullName) || f.GetFileName() is not { } file) continue;
            a.SetTag("code.filepath", file);
            a.SetTag("code.lineno", f.GetFileLineNumber());
            a.SetTag("code.namespace", t.FullName);
            a.SetTag("code.function", m.Name);
            return;
        }
    }
}
