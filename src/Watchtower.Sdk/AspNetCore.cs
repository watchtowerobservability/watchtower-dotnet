using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Logs;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace Watchtower;

public static class ServiceCollectionExtensions
{
    /// <summary>One call: traces (ASP.NET Core, HttpClient, EF Core spans), ILogger logs over OTLP,
    /// request exception capture, and the unhandled/unobserved hooks. Config defaults to <see cref="Config.FromEnv"/>.</summary>
    public static IServiceCollection AddWatchtower(this IServiceCollection services, Config? cfg = null, params string[] sources)
    {
        cfg ??= Config.FromEnv();
        services.AddOpenTelemetry()
            .WithTracing(b => b.AddWatchtower(cfg, sources)
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddEntityFrameworkCoreInstrumentation())
            .WithLogging(l => l
                .ConfigureResource(r => r.AddAttributes(cfg.ResourceAttributes()))
                .AddOtlpExporter(o => cfg.Apply(o, "logs")));
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IStartupFilter, CaptureStartupFilter>());
        services.TryAddSingleton<WatchtowerHooks>();
        return services;
    }

    /// <summary>Same as the services call, for the minimal-hosting builder.</summary>
    public static WebApplicationBuilder AddWatchtower(this WebApplicationBuilder builder, Config? cfg = null, params string[] sources)
    {
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
        app.Use(async (ctx, nxt) =>
        {
            try { await nxt(ctx); }
            catch (Exception ex) when (!ctx.RequestAborted.IsCancellationRequested)
            {
                ErrorCapture.Capture(ex, escaped: true);
                throw;
            }
        });
        next(app);
    };
}
