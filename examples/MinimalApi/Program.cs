using Watchtower;

// WT_INGEST_KEY, WT_OTLP_ENDPOINT, WT_SERVICE, WT_ENVIRONMENT, WT_RELEASE come from the environment.
var builder = WebApplication.CreateBuilder(args);
builder.AddWatchtower();

var app = builder.Build();
app.MapGet("/", () => "hello");
app.MapGet("/boom", () => { throw new InvalidOperationException("test error from the example"); });
app.Run();
