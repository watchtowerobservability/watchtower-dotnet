using System.Diagnostics;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Watchtower;

/// <summary>Bounded buffer; drops the oldest item when full.
/// shortcut: in memory only, a process restart loses it; upgrade to a file spool.</summary>
public sealed class OfflineBuffer<T>
{
    private readonly Queue<T> _q = new();
    private readonly int _max;
    private readonly object _lock = new();

    public OfflineBuffer(int max = 64) => _max = Math.Max(max, 1);

    public void Push(T item)
    {
        lock (_lock)
        {
            if (_q.Count >= _max) _q.Dequeue();
            _q.Enqueue(item);
        }
    }

    public List<T> Drain()
    {
        lock (_lock)
        {
            var all = _q.ToList();
            _q.Clear();
            return all;
        }
    }
}

/// <summary>Endpoint default, key header and wt.*-safe attributes. No product logic.</summary>
public sealed class Config
{
    public const string DefaultEndpoint = "http://localhost:4318";

    private readonly string? _key;

    public string Service { get; }
    public string Endpoint { get; }
    public IReadOnlyDictionary<string, object> Resource { get; }
    /// <summary>Returns the new value, or null to drop the attribute.</summary>
    public Func<string, object?, object?>? Redactor { get; }

    public Config(string service, string? endpoint = null, string? key = null,
        IReadOnlyDictionary<string, object>? resource = null, Func<string, object?, object?>? redactor = null)
    {
        Service = service;
        Endpoint = (endpoint ?? DefaultEndpoint).TrimEnd('/');
        _key = key;
        Resource = resource ?? new Dictionary<string, object>();
        Redactor = redactor;
    }

    /// <summary>Reads WT_ENDPOINT and WT_INGEST_KEY.</summary>
    public static Config FromEnv(string service)
    {
        static string? Get(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : null;
        return new Config(service, Get("WT_ENDPOINT"), Get("WT_INGEST_KEY"));
    }

    public string Headers => _key is null ? "" : $"authorization=Bearer {_key}";

    public Dictionary<string, object> ResourceAttributes() =>
        new Dictionary<string, object> { ["service.name"] = Service }
            .Concat(Redaction.DropReserved(Resource)).ToDictionary(p => p.Key, p => p.Value);

    // The key must never reach logs.
    public override string ToString() => $"Config(service={Service}, endpoint={Endpoint}, key=***)";
}

public static class Redaction
{
    public static bool Reserved(string key) => key.StartsWith("wt.", StringComparison.Ordinal);

    public static IEnumerable<KeyValuePair<string, T>> DropReserved<T>(IEnumerable<KeyValuePair<string, T>> attrs) =>
        attrs.Where(p => !Reserved(p.Key));

    /// <summary>Drops wt.* and applies the hook; a null result drops the attribute.</summary>
    public static Dictionary<string, object> Apply(IEnumerable<KeyValuePair<string, object?>> attrs, Func<string, object?, object?>? hook)
    {
        var o = new Dictionary<string, object>();
        foreach (var (k, v0) in DropReserved(attrs))
        {
            var v = hook is null ? v0 : hook(k, v0);
            if (v is not null) o[k] = v;
        }
        return o;
    }
}

/// <summary>Applies the redaction hook as an activity ends.</summary>
public sealed class RedactingProcessor : BaseProcessor<Activity>
{
    private readonly Func<string, object?, object?>? _hook;

    public RedactingProcessor(Func<string, object?, object?>? hook) => _hook = hook;

    public override void OnEnd(Activity a)
    {
        var tags = a.TagObjects.ToList();
        var kept = Redaction.Apply(tags.Select(t => new KeyValuePair<string, object?>(t.Key, t.Value)), _hook);
        foreach (var t in tags)
        {
            // SetTag(null) removes the tag.
            a.SetTag(t.Key, kept.TryGetValue(t.Key, out var v) ? v : null);
        }
    }
}

public static class Watchtower
{
    public const string SourceName = "Watchtower";

    /// <summary>Builds a TracerProvider exporting OTLP/HTTP to Watchtower. Dispose it on shutdown.</summary>
    public static TracerProvider Init(Config cfg, params string[] sources) =>
        Sdk.CreateTracerProviderBuilder()
            .ConfigureResource(r => r.AddAttributes(cfg.ResourceAttributes()))
            .AddSource(sources.Length == 0 ? [SourceName] : sources)
            .AddProcessor(new RedactingProcessor(cfg.Redactor))
            .AddOtlpExporter(o =>
            {
                o.Endpoint = new Uri($"{cfg.Endpoint}/v1/traces");
                o.Protocol = OtlpExportProtocol.HttpProtobuf;
                if (cfg.Headers.Length > 0) o.Headers = cfg.Headers;
            })
            .Build();
}
