# Watchtower.Sdk

Thin Watchtower distribution over the OpenTelemetry .NET SDK: `Authorization: Bearer` key header, endpoint default, offline buffer, `wt.*`-safe attributes, redaction hook, error capture with trace ids, ASP.NET Core and `ILogger` integration.

Status: 0.x, early. APIs may change between minor versions.

[![CI](https://github.com/watchtowerobservability/watchtower-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/watchtowerobservability/watchtower-dotnet/actions/workflows/ci.yml)

## Install

```sh
dotnet nuget add source https://nuget.pkg.github.com/watchtowerobservability/index.json -n watchtower -u <github-user> -p <token-with-read:packages>
dotnet add package Watchtower.Sdk
```

## Quick start (ASP.NET Core)

```csharp
using Watchtower;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddWatchtower();   // or builder.AddWatchtower()
var app = builder.Build();
app.Run();
```

Set `WT_INGEST_KEY` in the environment; never commit it. Runnable app: `examples/MinimalApi`.

Console or worker apps:

```csharp
using var tp = Watchtower.Watchtower.Init(Config.FromEnv("checkout"), "MyApp");
using var hooks = ErrorCapture.Install(tp);   // unhandled + unobserved task exceptions
try { Work(); } catch (Exception e) { var traceId = ErrorCapture.Capture(e); }
```

## Integrations

| Integration | How |
|---|---|
| ASP.NET Core | `AddWatchtower()`: request spans, exception capture middleware |
| HttpClient | client spans (included in `AddWatchtower()`) |
| EF Core | query spans via OpenTelemetry contrib (included in `AddWatchtower()`) |
| `ILogger` | logs exported over OTLP with trace correlation (included in `AddWatchtower()`) |
| Unhandled / unobserved | `ErrorCapture.Install()` (installed by `AddWatchtower()`) |
| Metrics | `AddWatchtower()` adds ASP.NET Core, HttpClient and .NET runtime metrics (GC, heap, thread pool, JIT, exceptions) over OTLP; meters named in `sources` are exported too. Console apps: `Signals.InitMetrics(cfg, "MyMeter")` |
| `ILogger` outside ASP.NET Core | `Signals.CreateLoggerFactory(cfg)` |
| Offline buffer | failed trace exports are held in memory (default 2048 spans) and retried; `WT_SPOOL_DIR` adds the OTLP exporter's disk retry for traces, logs and metrics |

Counters and histograms use delta temporality unless `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative`;
`OTEL_METRIC_EXPORT_INTERVAL` sets the export period. The disk retry is the exporter's own
(`OTEL_DOTNET_EXPERIMENTAL_OTLP_RETRY=disk`, experimental upstream, bounded by its own size limits). With
`services.AddWatchtower()` on a host built before the call, set those two `OTEL_DOTNET_EXPERIMENTAL_OTLP_*`
variables yourself; `builder.AddWatchtower()` and the console helpers set them from `WT_SPOOL_DIR`.

MAUI, desktop and mobile apps: not covered by this package yet (native crash handling and a client publishable key flow are planned). Use it for the backend of such apps.

### Embedded and in-process stores

`EmbeddedStores.ObserveMemoryCache(cache, "name")` (create the cache with `TrackStatistics = true`) reports
entries, hits, misses and size; `EmbeddedStores.ObserveFiles("sqlite", path, path + "-wal")` reports file and
WAL size for Microsoft.Data.Sqlite, LiteDB or DuckDB files; `EmbeddedStores.Observe(system, ns, read)` takes
any other store. Metrics are `wt.embedded.*` on the `Watchtower` meter. Dispose the handle to stop.

## Profiling

```csharp
using var profiler = Watchtower.Profiling.Profiler.FromEnv().Start();
```

A continuous wall-clock profiler with no native agent and no extra package. It opens an EventPipe session on its own process through the runtime's diagnostics server, reads the nettrace stream with our own parser, and folds the stacks. Every 15 s it posts them to `/ingest` as `<service>.wall`. The runtime's SampleProfiler records every managed thread's stack about once a millisecond, whether the thread is running or waiting. Method names come from the rundown at the end of each session. Each period also ends with a method rundown. Overhead has not been measured; test it under your own load before enabling it in production. Native frames show as `[native]`. The profiler needs the diagnostics server, so `DOTNET_EnableDiagnostics=0` turns it off. Uploads that fail are counted in `Dropped` and dropped. `Profiler.Capture(TimeSpan)` returns one window of folded stacks.

`Profiler.WithSpan(() => Work())` labels samples with the current `Activity`, so a trace links to its exact profile. By default it labels the calling thread until the function returns. Set `Profiler.AsyncSpanLabels = true` to let the span flow with the ExecutionContext, so code after an `await` is labeled on whichever thread it resumes, as is work the function starts. It is opt-in because its overhead has not been measured.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `WT_INGEST_KEY` | secret ingest key, sent as `Authorization: Bearer` | none |
| `WT_OTLP_ENDPOINT` | OTLP/HTTP base URL (`WT_ENDPOINT` is a deprecated alias) | `http://localhost:4318` |
| `WT_SERVICE` | `service.name` when not passed in code | `unknown_service` |
| `WT_ENVIRONMENT` | `deployment.environment` | unset |
| `WT_RELEASE` | `service.version` | unset |
| `WATCHTOWER_LOGS` | `on`/`off`: ILogger over OTLP (`OTEL_LOGS_EXPORTER=none` also turns it off) | `on` |
| `WATCHTOWER_METRICS` | `on`/`off`: metrics over OTLP (`OTEL_METRICS_EXPORTER=none` also turns it off) | `on` |
| `WT_SPOOL_DIR` | disk retry directory for all signals | unset |

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-dotnet`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
