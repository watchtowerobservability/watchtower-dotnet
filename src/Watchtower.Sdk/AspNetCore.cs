using Microsoft.AspNetCore.Builder;
using System.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Watchtower;

public static class ServiceCollectionExtensions
{
    /// <summary>One call: traces (ASP.NET Core, HttpClient, EF Core spans), ILogger logs and metrics
    /// (ASP.NET Core, HttpClient, .NET runtime, plus <paramref name="sources"/> as meter names) over OTLP,
    /// request exception capture, and the unhandled/unobserved hooks. Config defaults to <see cref="Config.FromEnv"/>.
    /// Logs and metrics follow <see cref="Signals.LogsOn"/> / <see cref="Signals.MetricsOn"/>.</summary>
    public static IServiceCollection AddWatchtower(this IServiceCollection services, Config? cfg = null, params string[] sources)
    {
        cfg ??= Config.FromEnv();
        Signals.UseSpoolFromEnv();
        var otel = services.AddOpenTelemetry()
            .WithTracing(b => b.AddWatchtower(cfg, sources)
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddEntityFrameworkCoreInstrumentation());
        if (Signals.LogsOn)
        {
            otel.WithLogging(l => l
                .ConfigureResource(r => r.AddAttributes(cfg.ResourceAttributes()))
                .AddOtlpExporter(o => cfg.Apply(o, "logs")));
        }
        if (Signals.MetricsOn)
        {
            otel.WithMetrics(m => m.AddWatchtower(cfg, sources)
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation());
        }
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStartupFilter, CaptureStartupFilter>());
        services.TryAddSingleton<WatchtowerHooks>();
        services.TryAddSingleton(cfg);
        return services;
    }

    /// <summary>Same as the services call, for the minimal-hosting builder.</summary>
    public static WebApplicationBuilder AddWatchtower(this WebApplicationBuilder builder, Config? cfg = null, params string[] sources)
    {
        // the exporters read their retry settings from the host configuration, built before this call
        if (System.Environment.GetEnvironmentVariable("WT_SPOOL_DIR") is { Length: > 0 } dir)
        {
            builder.Configuration["OTEL_DOTNET_EXPERIMENTAL_OTLP_RETRY"] ??= "disk";
            builder.Configuration["OTEL_DOTNET_EXPERIMENTAL_OTLP_DISK_RETRY_DIRECTORY_PATH"] ??= dir;
        }
        builder.Services.AddWatchtower(cfg, sources);
        return builder;
    }
}

/// <summary>Process-wide exception hooks; installed when the pipeline is built, removed on dispose.</summary>
internal sealed class WatchtowerHooks : IDisposable
{
    private readonly IDisposable _hooks;
    public WatchtowerHooks(IServiceProvider sp) => _hooks = ErrorCapture.Install(sp.GetService<TracerProvider>());
    public void Dispose() => _hooks.Dispose();
}

/// <summary>Outermost middleware: captures exceptions that escape the app, then rethrows.</summary>
internal sealed class CaptureStartupFilter(IServiceProvider sp) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        _ = sp.GetRequiredService<WatchtowerHooks>();
        StartCapture(sp.GetService<Config>());
        app.Use(async (ctx, nxt) =>
        {
            if (PayloadCapture.Active)
            {
                await WithPayload(ctx, nxt);
                return;
            }
            try { await nxt(ctx); }
            catch (Exception ex) when (!ctx.RequestAborted.IsCancellationRequested)
            {
                ErrorCapture.Capture(ex, escaped: true);
                throw;
            }
        });
        next(app);
    };

    /// <summary>Opt-in with WT_CAPTURE_RULES=1: fetch the payload capture rules in the background (APM-016).</summary>
    private static void StartCapture(Config? cfg)
    {
        if (cfg?.Key is not { } key || System.Environment.GetEnvironmentVariable("WT_CAPTURE_RULES") != "1") return;
        var api = System.Environment.GetEnvironmentVariable("WT_API_URL") is { Length: > 0 } a ? a : cfg.Endpoint;
        _ = PayloadCapture.LoadAsync(new HttpClient { Timeout = TimeSpan.FromSeconds(10) }, api, key, cfg.Service);
    }

    /// <summary>Tees up to 2 * HardMax bytes of the request and response bodies and records them
    /// on the request activity per the rule matching the route; exceptions still reach the capture above.</summary>
    private static async Task WithPayload(HttpContext ctx, RequestDelegate nxt)
    {
        ctx.Request.EnableBuffering();
        var original = ctx.Response.Body;
        var tee = new TeeStream(original);
        ctx.Response.Body = tee;
        try { await nxt(ctx); }
        catch (Exception ex) when (!ctx.RequestAborted.IsCancellationRequested)
        {
            ErrorCapture.Capture(ex, escaped: true);
            throw;
        }
        finally { ctx.Response.Body = original; }
        var req = new byte[2 * PayloadCapture.HardMax];
        ctx.Request.Body.Position = 0;
        var n = await ctx.Request.Body.ReadAtLeastAsync(req, req.Length, throwOnEndOfStream: false);
        var route = (ctx.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? ctx.Request.Path.Value ?? "";
        PayloadCapture.Record(Activity.Current, "/" + route.TrimStart('/'), ctx.Request.ContentType, req[..n],
            ctx.Response.ContentType, tee.Captured);
    }
}
