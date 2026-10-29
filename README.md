# Watchtower.Sdk

Thin Watchtower distribution over the OpenTelemetry .NET SDK: `Authorization: Bearer` key header, endpoint default, `wt.*`-safe attributes, redaction hook.

Status: 0.x, early. APIs may change between minor versions.

## Install

```sh
dotnet nuget add source https://nuget.pkg.github.com/watchtowerobservability/index.json -n watchtower -u <github-user> -p <token-with-read:packages>
dotnet add package Watchtower.Sdk
```

## Use

```csharp
using var tp = Watchtower.Init(Config.FromEnv("checkout"), "MyApp");
```

The ingest key is read from the environment (`WT_INGEST_KEY`); never commit it.

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-dotnet`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
