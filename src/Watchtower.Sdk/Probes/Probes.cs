using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using HarmonyLib;

namespace Watchtower.Probes;

/// <summary>
/// Dynamic probes for running .NET code (PLT-044), with the safety model of the Python, Go and
/// browser agents: off until <see cref="Start"/> is called, read-only and bounded.
///
/// A live probe on <c>Namespace.Type#Method</c> patches that method (all overloads) with a
/// prefix. On a call the prefix reads the arguments and <c>this</c> by field reflection only (no
/// property getter, ToString or other user method runs; depth at most 3, 50 fields per object),
/// evaluates the condition subset, applies the per-minute rate limit, flattens the values to
/// <c>code.snapshot.*</c> (8 KiB, 1 KiB per value) and adds a <c>probe.snapshot</c> event to the
/// current Activity. With no live probe nothing is patched.
///
/// Kind <c>span</c> starts an Activity <c>probe &lt;method&gt;</c> (source "Watchtower", which
/// AddWatchtower listens to) in the prefix, so it is current for the call, and stops it in a
/// finalizer, marking it an error when the call throws. Kind <c>span_decoration</c> sets
/// <c>capture.tags</c> (templates like <c>{user.id}</c> over the arguments) on Activity.Current.
/// shortcut: an async method's span ends when it returns its Task, not when the Task completes;
/// wrap the continuation when users ask.
/// shortcut: .NET probes are method-entry only; line probes need IL offsets from the PDB, add
/// them with System.Reflection.Metadata when users ask.
/// </summary>
public sealed class ProbeSet
{
    private const int ValueMax = 1024;
    private const int MaxFields = 50;
    private static readonly string[] Refused = { "System.", "Microsoft.", "HarmonyLib.", "MonoMod.", "Watchtower.", "OpenTelemetry." };
    private static ProbeSet? _active;
    private static readonly ConcurrentDictionary<MethodBase, List<Live>> ByMethod = new();
    private static readonly ActivitySource Source = new("Watchtower");
    private static readonly System.Text.RegularExpressions.Regex Template = new(@"\{([A-Za-z_][\w.]*)\}");

    internal sealed class Live
    {
        public required JsonElement Def;
        public required Func<IReadOnlyDictionary<string, object?>, bool> Ok;
        public required string Id;
        public long Win;
        public int N;

        public string Kind => Def.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() ?? "" : "snapshot";

        public int Num(string k, int dflt, int max) =>
            Math.Min(Def.TryGetProperty(k, out var e) && e.ValueKind == JsonValueKind.Number && e.GetInt32() > 0 ? e.GetInt32() : dflt, max);
    }

    private readonly string _endpoint, _key, _query;
    private readonly Action<string, Dictionary<string, string>> _emit;
    private readonly Func<long> _nowMs;
    private readonly Harmony? _harmony;
    private readonly HttpClient _http = new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(10) };
    private string _etag = "";

    public ProbeSet(string endpoint, string key, string service, string env = "", string version = "",
        Action<string, Dictionary<string, string>>? emit = null, Func<long>? nowMs = null, bool patch = true)
    {
        _endpoint = endpoint.TrimEnd('/');
        _key = key;
        _query = $"service={Uri.EscapeDataString(service)}&env={Uri.EscapeDataString(env)}&version={Uri.EscapeDataString(version)}"
            + "&kinds=log,snapshot,metric,span,span_decoration";
        _emit = emit ?? DefaultEmit;
        _nowMs = nowMs ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        _harmony = patch ? new Harmony("watchtower.probes") : null;
    }

    internal Dictionary<string, Live> Current { get; private set; } = new();

    /// <summary>Replaces the probe set; probes outside the subset or on refused code are skipped.</summary>
    public void Set(IEnumerable<JsonElement> defs)
    {
        var next = new Dictionary<string, Live>();
        foreach (var d in defs)
        {
            try
            {
                var id = d.GetProperty("id").GetString() ?? "";
                var cond = d.TryGetProperty("condition", out var c) ? c.GetString() : null;
                next[id] = new Live { Def = d.Clone(), Ok = Condition.Compile(cond), Id = id };
            }
            catch (Exception e) when (e is ArgumentException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                // a probe we cannot evaluate is skipped
            }
        }
        Current = next;
        if (_harmony is not null) Repatch(next.Values);
    }

    private void Repatch(IEnumerable<Live> live)
    {
        _harmony!.UnpatchAll(_harmony.Id);
        ByMethod.Clear();
        _active = this;
        var prefix = new HarmonyMethod(typeof(ProbeSet).GetMethod(nameof(Prefix), BindingFlags.Static | BindingFlags.NonPublic));
        var finalizer = new HarmonyMethod(typeof(ProbeSet).GetMethod(nameof(Finalizer), BindingFlags.Static | BindingFlags.NonPublic));
        foreach (var l in live)
        {
            foreach (var m in Resolve(l))
            {
                ByMethod.AddOrUpdate(m, _ => new List<Live> { l }, (_, list) => { list.Add(l); return list; });
                try { _harmony.Patch(m, prefix: prefix, finalizer: finalizer); } catch (Exception) { ByMethod.TryRemove(m, out _); }
            }
        }
    }

    private static IEnumerable<MethodBase> Resolve(Live l)
    {
        if (!l.Def.TryGetProperty("location", out var loc) || !loc.TryGetProperty("function", out var f)) yield break;
        var fn = f.GetString() ?? "";
        var hash = fn.LastIndexOf('#');
        if (hash <= 0) yield break; // a bare name would scan every type
        string typeName = fn[..hash], method = fn[(hash + 1)..];
        if (Refused.Any(typeName.StartsWith)) yield break;
        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            var t = asm.GetType(typeName, throwOnError: false);
            if (t is null) continue;
            const BindingFlags all = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly;
            foreach (var m in t.GetMethods(all))
                if (m.Name == method && !m.IsAbstract && !m.ContainsGenericParameters) yield return m;
        }
    }

    // Harmony prefix: runs on the caller's thread at method entry; never throws into it.
    private static void Prefix(MethodBase __originalMethod, object[] __args, object? __instance, out object? __state)
    {
        __state = null;
        try
        {
            if (_active is null || !ByMethod.TryGetValue(__originalMethod, out var probes)) return;
            var vars = new Dictionary<string, object?>();
            var ps = __originalMethod.GetParameters();
            for (var i = 0; i < ps.Length && i < __args.Length; i++) vars[ps[i].Name ?? $"arg{i}"] = Plain(__args[i], 1);
            if (__instance is not null) vars["this"] = Plain(__instance, 1);
            var fn = $"{__originalMethod.DeclaringType?.FullName}#{__originalMethod.Name}";
            var file = __originalMethod.DeclaringType?.Assembly.GetName().Name ?? "";
            foreach (var l in probes.ToArray())
            {
                switch (l.Kind)
                {
                    case "span" when _active.Allowed(l, vars):
                        var a = Source.StartActivity("probe " + __originalMethod.Name);
                        if (a is null) break; // no listener for the "Watchtower" source
                        a.SetTag("probe.id", l.Id).SetTag("code.function", fn).SetTag("code.filepath", file);
                        ((List<Activity>)(__state ??= new List<Activity>())).Add(a);
                        break;
                    case "span_decoration" when _active.Allowed(l, vars):
                        foreach (var (k, v) in Tags(l.Def, vars)) Activity.Current?.SetTag(k, v);
                        break;
                    case "span" or "span_decoration":
                        break;
                    default:
                        _active.Hit(l.Id, fn, file, 0, vars);
                        break;
                }
            }
        }
        catch (Exception)
        {
            // the app must never fail because of a probe
        }
    }

    // Harmony finalizer: ends the call's probe spans, innermost first; void, so the exception is untouched.
    private static void Finalizer(Exception? __exception, object? __state)
    {
        if (__state is not List<Activity> spans) return;
        for (var i = spans.Count - 1; i >= 0; i--)
        {
            try
            {
                if (__exception is not null)
                {
                    spans[i].SetStatus(ActivityStatusCode.Error, __exception.Message);
                    spans[i].SetTag("exception.type", __exception.GetType().FullName);
                }
                spans[i].Stop();
            }
            catch (Exception)
            {
                // never into the app
            }
        }
    }

    /// <summary>Fills <c>{a.b}</c> from the values (missing names render empty), cut to 1 KiB.</summary>
    public static string Render(string template, IReadOnlyDictionary<string, object?> vars)
    {
        var s = Template.Replace(template, m => Condition.Get(vars, m.Groups[1].Value) switch
        {
            null => "",
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            var o => o.ToString() ?? "",
        });
        return s.Length > ValueMax ? s[..ValueMax] : s;
    }

    /// <summary>The span_decoration tags of a probe (wt.* names are never set).</summary>
    public static Dictionary<string, string> Tags(JsonElement def, IReadOnlyDictionary<string, object?> vars)
    {
        var out_ = new Dictionary<string, string>();
        if (!def.TryGetProperty("capture", out var cap) || cap.ValueKind != JsonValueKind.Object
            || !cap.TryGetProperty("tags", out var tags) || tags.ValueKind != JsonValueKind.Array) return out_;
        foreach (var t in tags.EnumerateArray())
        {
            var name = t.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            var value = t.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
            if (name.Length > 0 && !name.StartsWith("wt.", StringComparison.Ordinal)) out_[name] = Render(value, vars);
        }
        return out_;
    }

    /// <summary>Not expired, inside the per-minute budget and the condition holds (counts the hit).</summary>
    internal bool Allowed(Live p, IReadOnlyDictionary<string, object?> vars)
    {
        var t = _nowMs();
        if (p.Def.TryGetProperty("expires_at", out var exp) && exp.ValueKind == JsonValueKind.Number && t >= exp.GetDouble() * 1000) return false;
        lock (p)
        {
            var minute = t / 60_000;
            if (p.Win != minute) { p.Win = minute; p.N = 0; }
            if (p.N >= p.Num("max_rate_per_min", 60, 60) || !p.Ok(vars)) return false;
            p.N++;
            return true;
        }
    }

    /// <summary>Handles one hit with plain values.</summary>
    public void Hit(string id, string function, string file, int line, IReadOnlyDictionary<string, object?> vars)
    {
        if (!Current.TryGetValue(id, out var p) || !Allowed(p, vars)) return;
        var attrs = new Dictionary<string, string>
        {
            ["probe.id"] = id, ["code.function"] = function, ["code.filepath"] = file, ["code.lineno"] = line.ToString(CultureInfo.InvariantCulture),
        };
        if (p.Def.TryGetProperty("message", out var msg) && msg.ValueKind == JsonValueKind.String && msg.GetString() is { Length: > 0 } s) attrs["probe.message"] = s;
        int depth = 3, max = 8192;
        if (p.Def.TryGetProperty("capture", out var cap) && cap.ValueKind == JsonValueKind.Object)
        {
            if (cap.TryGetProperty("locals_depth", out var ld) && ld.ValueKind == JsonValueKind.Number && ld.GetInt32() > 0) depth = Math.Min(ld.GetInt32(), 3);
            if (cap.TryGetProperty("max_bytes", out var mb) && mb.ValueKind == JsonValueKind.Number && mb.GetInt32() > 0) max = Math.Min(mb.GetInt32(), 8192);
        }
        foreach (var (k, v) in Capture(vars, depth, max)) attrs["code.snapshot." + k] = v;
        try { _emit("probe.snapshot", attrs); } catch (Exception) { /* never into the app */ }
    }

    /// <summary>A value as a plain value, read by field reflection only.</summary>
    public static object? Plain(object? v, int d)
    {
        switch (v)
        {
            case null: return null;
            case string s: return s;
            case bool b: return b;
            case char c: return c.ToString();
            case float or double or decimal: return Convert.ToDouble(v, CultureInfo.InvariantCulture);
            case ulong u: return u <= long.MaxValue ? (long)u : (double)u;
            case sbyte or byte or short or ushort or int or uint or long: return Convert.ToInt64(v, CultureInfo.InvariantCulture);
            case Enum e: return Enum.GetName(e.GetType(), e) ?? Convert.ToInt64(e, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture);
            case DateTime or DateTimeOffset or Guid or TimeSpan: return ((IFormattable)v).ToString(null, CultureInfo.InvariantCulture);
        }
        if (d > 3) return "[depth limit]";
        if (v is Array a)
        {
            var list = new List<object?>();
            for (var i = 0; i < a.Length && i < MaxFields; i++) list.Add(Plain(a.GetValue(i), d + 1));
            return list;
        }
        var o = new Dictionary<string, object?>();
        foreach (var f in v.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).Take(MaxFields))
        {
            var name = f.Name.StartsWith('<') && f.Name.Contains(">k__BackingField") ? f.Name[1..f.Name.IndexOf('>')] : f.Name;
            o[name] = Plain(f.GetValue(v), d + 1);
        }
        return o;
    }

    /// <summary>Flattens to dotted names: nesting past depth collapses, values cut to 1 KiB, total to maxBytes.</summary>
    public static Dictionary<string, string> Capture(IReadOnlyDictionary<string, object?> vars, int depth, int maxBytes)
    {
        var out_ = new Dictionary<string, string>();
        var used = 0;
        void Put(string name, string val)
        {
            var s = val.Length > ValueMax ? val[..ValueMax] : val;
            if (used + name.Length + s.Length > maxBytes) return;
            used += name.Length + s.Length;
            out_[name] = s;
        }
        void Walk(string prefix, object? v, int d)
        {
            switch (v)
            {
                case IReadOnlyDictionary<string, object?> when d > depth: Put(prefix, "[depth limit]"); break;
                case IReadOnlyDictionary<string, object?> m:
                    foreach (var k in m.Keys.OrderBy(k => k, StringComparer.Ordinal)) Walk(prefix.Length == 0 ? k : $"{prefix}.{k}", m[k], d + 1);
                    break;
                case List<object?> when d > depth: Put(prefix, "[depth limit]"); break;
                case List<object?> l:
                    for (var i = 0; i < l.Count; i++) Walk(prefix.Length == 0 ? $"{i}" : $"{prefix}.{i}", l[i], d + 1);
                    break;
                case null: Put(prefix, "null"); break;
                case bool b: Put(prefix, b ? "true" : "false"); break;
                case IFormattable f: Put(prefix, f.ToString(null, CultureInfo.InvariantCulture)); break;
                default: Put(prefix, v.ToString() ?? ""); break; // only strings reach here
            }
        }
        Walk("", vars, 0);
        return out_;
    }

    /// <summary>Refreshes the probe set from <c>GET /v1/probes/active</c>; failures wait for the next poll.</summary>
    public async Task PollAsync(CancellationToken ct = default)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{_endpoint}/v1/probes/active?{_query}");
            req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + _key);
            if (_etag.Length > 0) req.Headers.TryAddWithoutValidation("If-None-Match", _etag);
            using var r = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if ((int)r.StatusCode != 200 || r.Content.Headers.ContentLength > 4 << 20) return;
            _etag = r.Headers.ETag?.ToString() ?? "";
            using var doc = JsonDocument.Parse(await r.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            if (doc.RootElement.TryGetProperty("probes", out var p) && p.ValueKind == JsonValueKind.Array) Set(p.EnumerateArray().Select(e => e.Clone()).ToList());
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            // retried on the next poll
        }
    }

    private static void DefaultEmit(string name, Dictionary<string, string> attrs)
    {
        var tags = new ActivityTagsCollection();
        foreach (var (k, v) in attrs) tags[k] = v;
        Activity.Current?.AddEvent(new ActivityEvent(name, tags: tags));
    }

    /// <summary>Polls active probes every interval in the background; dispose the result to stop.</summary>
    public static IDisposable Start(string? endpoint = null, string? key = null, string? service = null, string env = "", string version = "",
        TimeSpan? interval = null, Action<string, Dictionary<string, string>>? emit = null)
    {
        var set = new ProbeSet(endpoint ?? Environment.GetEnvironmentVariable("WT_API_URL") ?? "https://api.watchtower.dev",
            key ?? Environment.GetEnvironmentVariable("WT_INGEST_KEY") ?? "",
            service ?? Environment.GetEnvironmentVariable("OTEL_SERVICE_NAME") ?? "unknown", env, version, emit);
        var cts = new CancellationTokenSource();
        var every = interval is { } i && i > TimeSpan.FromSeconds(5) ? i : TimeSpan.FromSeconds(30);
        _ = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                await set.PollAsync(cts.Token).ConfigureAwait(false);
                try { await Task.Delay(every, cts.Token).ConfigureAwait(false); } catch (TaskCanceledException) { }
            }
        });
        return new Stop(() => { cts.Cancel(); set.Set(Array.Empty<JsonElement>()); });
    }

    private sealed class Stop(Action a) : IDisposable
    {
        public void Dispose() => a();
    }
}
