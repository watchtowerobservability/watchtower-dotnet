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
    public string? Environment { get; }
    public string? Release { get; }
    /// <summary>Max spans held in memory while the endpoint is unreachable.</summary>
    public int BufferSize { get; }
    /// <summary>Returns the new value, or null to drop the attribute.</summary>
    public Func<string, object?, object?>? Redactor { get; }

    public Config(string service, string? endpoint = null, string? key = null,
        IReadOnlyDictionary<string, object>? resource = null, Func<string, object?, object?>? redactor = null,
        string? environment = null, string? release = null, int bufferSize = 2048)
    {
        Environment = environment;
        Release = release;
        BufferSize = bufferSize;
        Service = service;
        Endpoint = (endpoint ?? DefaultEndpoint).TrimEnd('/');
        _key = key;
        Resource = resource ?? new Dictionary<string, object>();
        Redactor = redactor;
    }

    /// <summary>Reads WT_SERVICE (used when <paramref name="service"/> is null), WT_OTLP_ENDPOINT
    /// (WT_ENDPOINT is a deprecated alias), WT_INGEST_KEY, WT_ENVIRONMENT, WT_RELEASE.</summary>
    public static Config FromEnv(string? service = null)
    {
        static string? Get(string k) => System.Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : null;
        return new Config(service ?? Get("WT_SERVICE") ?? "unknown_service",
            Get("WT_OTLP_ENDPOINT") ?? Get("WT_ENDPOINT"), Get("WT_INGEST_KEY"),
            environment: Get("WT_ENVIRONMENT"), release: Get("WT_RELEASE"));
    }

    /// <summary>Points an OTLP exporter at this config for one signal ("traces" or "logs").</summary>
    public void Apply(OtlpExporterOptions o, string signal)
    {
        o.Endpoint = new Uri($"{Endpoint}/v1/{signal}");
        o.Protocol = OtlpExportProtocol.HttpProtobuf;
        if (Headers.Length > 0) o.Headers = Headers;
    }

    public string Headers => _key is null ? "" : $"authorization=Bearer {_key}";

    public Dictionary<string, object> ResourceAttributes() =>
        new Dictionary<string, object> { ["service.name"] = Service }
            .Concat(Environment is null ? [] : [new KeyValuePair<string, object>("deployment.environment", Environment)])
            .Concat(Release is null ? [] : [new KeyValuePair<string, object>("service.version", Release)])
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

    /// <summary>Resource, sources (plus "Watchtower"), redaction, and an OTLP/HTTP export that
    /// buffers failed batches in memory and retries them on the next export.</summary>
    public static TracerProviderBuilder AddWatchtower(this TracerProviderBuilder b, Config cfg, params string[] sources)
    {
        var otlp = new OtlpExporterOptions();
        cfg.Apply(otlp, "traces");
        return b.ConfigureResource(r => r.AddAttributes(cfg.ResourceAttributes()))
            .AddSource(sources.Append(SourceName).Distinct().ToArray())
            .AddProcessor(new RedactingProcessor(cfg.Redactor))
            .AddProcessor(new BatchActivityExportProcessor(
                new BufferingExporter(new OtlpTraceExporter(otlp), new OfflineBuffer<Activity>(cfg.BufferSize))));
    }

    /// <summary>Builds a TracerProvider exporting OTLP/HTTP to Watchtower. Dispose it on shutdown.</summary>
    public static TracerProvider Init(Config cfg, params string[] sources) =>
        Sdk.CreateTracerProviderBuilder().AddWatchtower(cfg, sources).Build();
}
