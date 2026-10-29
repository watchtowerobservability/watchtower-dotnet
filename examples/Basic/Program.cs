using System.Diagnostics;
using Watchtower;

// Reads WT_INGEST_KEY, WT_OTLP_ENDPOINT, WT_SERVICE, WT_ENVIRONMENT, WT_RELEASE.
using var tp = Watchtower.Watchtower.Init(Config.FromEnv("example-dotnet"), "Example");
using var source = new ActivitySource("Example");
using (source.StartActivity("hello")) { }
