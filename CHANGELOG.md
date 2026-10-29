# Changelog

## 0.1.0

- OTLP/HTTP trace export over the OpenTelemetry .NET SDK with `Authorization: Bearer` key, `wt.*`-safe attributes and redaction hook.
- Error capture: `ErrorCapture.Capture`, AppDomain unhandled and TaskScheduler unobserved hooks (`ErrorCapture.Install`), trace ids on every captured error.
- ASP.NET Core: `services.AddWatchtower()` / `builder.AddWatchtower()` with request, HttpClient and EF Core spans, `ILogger` logs over OTLP, and exception capture middleware.
- `OfflineBuffer` wired into the trace export path: failed batches are retried with the next export.
- Configuration from `WT_INGEST_KEY`, `WT_OTLP_ENDPOINT` (`WT_ENDPOINT` deprecated alias), `WT_SERVICE`, `WT_ENVIRONMENT`, `WT_RELEASE`.
