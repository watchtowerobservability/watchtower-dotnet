using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;

namespace Watchtower;

/// <summary>Logs and metrics over the official OpenTelemetry .NET SDK, exported like traces.
/// <c>WATCHTOWER_LOGS</c> / <c>WATCHTOWER_METRICS</c> (default on; <c>OTEL_*_EXPORTER=none</c>
/// also turns a signal off). <c>WT_SPOOL_DIR</c> turns on the OTLP exporter's own disk retry for
/// every signal (<c>OTEL_DOTNET_EXPERIMENTAL_OTLP_RETRY=disk</c>); LogRecord and Metric objects are
/// pooled by the SDK, so they cannot sit in the in-memory span buffer.</summary>
public static class Signals
{
    public static bool LogsOn => On("WATCHTOWER_LOGS", "OTEL_LOGS_EXPORTER");
    public static bool MetricsOn => On("WATCHTOWER_METRICS", "OTEL_METRICS_EXPORTER");

    internal static bool On(string env, string otelEnv)
    {
        if (string.Equals(Get(otelEnv), "none", StringComparison.OrdinalIgnoreCase)) return false;
        return (Get(env) ?? "on").ToLowerInvariant() is not ("off" or "false" or "0" or "no");
    }

    private static string? Get(string k) => System.Environment.GetEnvironmentVariable(k)?.Trim() is { Length: > 0 } v ? v : null;

    /// <summary>Delta for counters and histograms (our ingest default) unless
    /// <c>OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative</c>.</summary>
    public static MetricReaderTemporalityPreference Temporality() =>
        string.Equals(Get("OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE"), "cumulative", StringComparison.OrdinalIgnoreCase)
            ? MetricReaderTemporalityPreference.Cumulative
            : MetricReaderTemporalityPreference.Delta;

    /// <summary>With <c>WT_SPOOL_DIR</c> set, failed OTLP batches of all signals go to that directory and are
    /// retried by the exporter. Must run before the providers are built; an explicit OTEL_ setting wins.</summary>
    public static void UseSpoolFromEnv()
    {
        if (Get("WT_SPOOL_DIR") is not { } dir) return;
        if (Get("OTEL_DOTNET_EXPERIMENTAL_OTLP_RETRY") is null)
            System.Environment.SetEnvironmentVariable("OTEL_DOTNET_EXPERIMENTAL_OTLP_RETRY", "disk");
        if (Get("OTEL_DOTNET_EXPERIMENTAL_OTLP_DISK_RETRY_DIRECTORY_PATH") is null)
            System.Environment.SetEnvironmentVariable("OTEL_DOTNET_EXPERIMENTAL_OTLP_DISK_RETRY_DIRECTORY_PATH", dir);
    }

    /// <summary>Resource, meters (plus "Watchtower"), .NET runtime metrics (GC, heap, thread pool, JIT,
    /// exceptions) and a periodic OTLP/HTTP export; OTEL_METRIC_EXPORT_INTERVAL applies.</summary>
    public static MeterProviderBuilder AddWatchtower(this MeterProviderBuilder b, Config cfg, params string[] meters) =>
        b.ConfigureResource(r => r.AddAttributes(cfg.ResourceAttributes()))
            .AddMeter(meters.Append(Watchtower.SourceName).Distinct().ToArray())
            .AddRuntimeInstrumentation()
            .AddOtlpExporter((o, reader) =>
            {
                cfg.Apply(o, "metrics");
                reader.TemporalityPreference = Temporality();
            });

    /// <summary>ILogger records over OTLP/HTTP; trace and span ids come from <c>Activity.Current</c>.</summary>
    public static OpenTelemetryLoggerOptions AddWatchtower(this OpenTelemetryLoggerOptions o, Config cfg)
    {
        o.SetResourceBuilder(ResourceBuilder.CreateDefault().AddAttributes(cfg.ResourceAttributes()));
        o.IncludeFormattedMessage = true;
        o.IncludeScopes = true;
        if (LogCallerProcessor.Enabled) o.AddProcessor(new LogCallerProcessor());
        return o.AddOtlpExporter(e => cfg.Apply(e, "logs"));
    }

    /// <summary>Console or worker apps: a MeterProvider exporting to Watchtower, or null when metrics are off. Dispose it on shutdown.</summary>
    public static MeterProvider? InitMetrics(Config cfg, params string[] meters)
    {
        if (!MetricsOn) return null;
        UseSpoolFromEnv();
        return Sdk.CreateMeterProviderBuilder().AddWatchtower(cfg, meters).Build();
    }

    /// <summary>Console or worker apps: an ILoggerFactory whose loggers export to Watchtower (no provider when logs are off). Dispose it on shutdown to flush.</summary>
    public static ILoggerFactory CreateLoggerFactory(Config cfg)
    {
        UseSpoolFromEnv();
        return LoggerFactory.Create(l =>
        {
            if (LogsOn) l.AddOpenTelemetry(o => o.AddWatchtower(cfg));
        });
    }
}
