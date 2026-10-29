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
| Offline buffer | failed trace exports are held in memory (default 2048 spans) and retried |

Logs are not buffered offline yet, and the buffer is in memory only.

MAUI, desktop and mobile apps: not covered by this package yet (native crash handling and a client publishable key flow are planned). Use it for the backend of such apps.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `WT_INGEST_KEY` | secret ingest key, sent as `Authorization: Bearer` | none |
| `WT_OTLP_ENDPOINT` | OTLP/HTTP base URL (`WT_ENDPOINT` is a deprecated alias) | `http://localhost:4318` |
| `WT_SERVICE` | `service.name` when not passed in code | `unknown_service` |
| `WT_ENVIRONMENT` | `deployment.environment` | unset |
| `WT_RELEASE` | `service.version` | unset |

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-dotnet`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
