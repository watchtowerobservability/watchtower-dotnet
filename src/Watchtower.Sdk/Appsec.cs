using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Watchtower;

/// <summary>The verdict on one request: <c>allow</c>, <c>monitor</c> or <c>block</c>.</summary>
public sealed record AppsecDecision(string Action, string? RuleId = null, string? Category = null, string? Match = null);

/// <summary>
/// App and API Protection in-app WAF, the same behavior as the Node, Python and Go agents.
/// <see cref="Start"/> polls <c>GET /v1/appsec/ruleset</c> (an ingestion key with scope <c>probes:read</c>,
/// ETag, every <c>poll_s</c>): the mode (<c>monitor</c> or <c>block</c>), the enabled pattern rules and the
/// denylist. <see cref="UseWatchtowerAppsec"/> adds a middleware that inspects every request before the app:
/// path, query, User-Agent and the other header values, percent-decoded once, against the rules the worker
/// runs over stored spans. A match is recorded on the current activity (<c>appsec.event</c>,
/// <c>appsec.rule_id</c>, <c>appsec.category</c>, <c>appsec.blocked</c>); in <c>block</c> mode, and for
/// denylisted IPs or users in either mode, the request gets 403 problem+json and the app never runs. Add it
/// after the OpenTelemetry instrumentation so the server activity is current. Rules match case-insensitively
/// with a 50 ms match timeout (a slower one counts as no match); one .NET cannot compile is skipped.
/// shortcut: trusts X-Forwarded-For for the client IP; run behind a proxy that overwrites it.
/// </summary>
public static class Appsec
{
    private sealed record Rule(string Id, string Category, Regex Re, string[] Fields);

    private sealed record State(bool Block, Rule[] Rules, Dictionary<string, double> Ip, Dictionary<string, double> User);

    private const string Problem = "{\"type\":\"about:blank\",\"title\":\"Forbidden\",\"status\":403,\"detail\":\"Request blocked by Watchtower App and API Protection\"}";
    private static volatile State _state = new(false, [], new(), new());
    private static CancellationTokenSource? _poller;

    private static Dictionary<string, double> Expiry(JsonElement e)
    {
        var d = new Dictionary<string, double>();
        if (e.ValueKind != JsonValueKind.Array) return d;
        foreach (var x in e.EnumerateArray())
        {
            if (x.ValueKind != JsonValueKind.Object || !x.TryGetProperty("value", out var v) || v.ValueKind != JsonValueKind.String) continue;
            var value = v.GetString();
            if (string.IsNullOrEmpty(value)) continue;
            d[value] = x.TryGetProperty("expires_at", out var t) && t.ValueKind == JsonValueKind.Number ? t.GetDouble() : double.PositiveInfinity;
        }
        return d;
    }

    /// <summary>Replace the active ruleset (the JSON document the edge serves; null clears it).</summary>
    public static void SetRuleset(JsonElement? doc)
    {
        if (doc is not { ValueKind: JsonValueKind.Object } r)
        {
            _state = new(false, [], new(), new());
            return;
        }
        var rules = new List<Rule>();
        if (r.TryGetProperty("rules", out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var rule in list.EnumerateArray())
            {
                if (rule.ValueKind != JsonValueKind.Object || !rule.TryGetProperty("pattern", out var p) || p.ValueKind != JsonValueKind.String) continue;
                try
                {
                    var fields = rule.TryGetProperty("fields", out var f) && f.ValueKind == JsonValueKind.Array
                        ? f.EnumerateArray().Select(x => x.GetString() ?? "").ToArray() : [];
                    var str = (string k) => rule.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
                    rules.Add(new Rule(str("id"), str("category"),
                        new Regex(p.GetString()!, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)), fields));
                }
                catch (ArgumentException)
                {
                    // not portable to .NET: the worker still evaluates it
                }
            }
        }
        var deny = r.TryGetProperty("denylist", out var dl) ? dl : default;
        JsonElement Get(string k) => deny.ValueKind == JsonValueKind.Object && deny.TryGetProperty(k, out var v) ? v : default;
        var block = r.TryGetProperty("mode", out var m) && m.ValueKind == JsonValueKind.String && m.GetString() == "block";
        _state = new(block, rules.ToArray(), Expiry(Get("ip")), Expiry(Get("user")));
    }

    public static bool Active { get { var s = _state; return s.Rules.Length > 0 || s.Ip.Count > 0 || s.User.Count > 0; } }

    private static bool Listed(Dictionary<string, double> m, string? v, double now)
        => !string.IsNullOrEmpty(v) && m.TryGetValue(v, out var until) && until > now;

    /// <summary>Whether <paramref name="userId"/> is denylisted (call after authentication to refuse a listed user).</summary>
    public static bool UserBlocked(string? userId, double? now = null)
        => Listed(_state.User, userId, now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0);

    /// <summary>Judge one request: keys <c>path</c>, <c>query</c>, <c>user_agent</c>, <c>headers</c>, <c>body</c>, <c>ip</c>, <c>user</c>.</summary>
    public static AppsecDecision Inspect(IReadOnlyDictionary<string, string> req, double? now = null)
    {
        var s = _state;
        var t = now ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        req.TryGetValue("ip", out var ip);
        req.TryGetValue("user", out var user);
        if (Listed(s.Ip, ip, t) || Listed(s.User, user, t)) return new("block", "denylist", "abuse");
        foreach (var rule in s.Rules)
        {
            foreach (var f in rule.Fields)
            {
                if (!req.TryGetValue(f, out var v) || v.Length == 0) continue;
                try
                {
                    var m = rule.Re.Match(v);
                    if (m.Success) return new(s.Block ? "block" : "monitor", rule.Id, rule.Category, m.Value.Length > 200 ? m.Value[..200] : m.Value);
                }
                catch (RegexMatchTimeoutException)
                {
                    // a pattern that runs away on this input counts as no match
                }
            }
        }
        return new("allow");
    }

    private static string Decode(string? s, bool plusIsSpace)
    {
        if (string.IsNullOrEmpty(s)) return "";
        try { return Uri.UnescapeDataString(plusIsSpace ? s.Replace('+', ' ') : s); }
        catch (UriFormatException) { return s; }
    }

    /// <summary>The request fields the rules read.</summary>
    public static Dictionary<string, string> FromRequest(HttpRequest r, string? user = null)
    {
        var others = new StringBuilder();
        foreach (var h in r.Headers)
        {
            if (string.Equals(h.Key, "User-Agent", StringComparison.OrdinalIgnoreCase)) continue;
            others.Append(h.Value.ToString()).Append('\n');
        }
        var xff = r.Headers["X-Forwarded-For"].ToString();
        var ip = xff.Length > 0 ? xff.Split(',')[0].Trim()
            : r.Headers["X-Real-IP"].ToString() is { Length: > 0 } real ? real : r.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
        var raw = r.HttpContext.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(raw)) raw = r.Path.Value ?? "";
        var d = new Dictionary<string, string>
        {
            ["path"] = Decode(raw.Split('?', 2)[0], false),
            ["query"] = Decode(r.QueryString.Value?.TrimStart('?'), true),
            ["user_agent"] = r.Headers.UserAgent.ToString(),
            ["headers"] = others.ToString().TrimEnd('\n'),
            ["ip"] = ip,
        };
        if (user != null) d["user"] = user;
        return d;
    }

    /// <summary>Record a decision on the current activity.</summary>
    public static void Annotate(AppsecDecision d, string? ip = null)
    {
        var a = Activity.Current;
        if (a is null) return;
        if (!string.IsNullOrEmpty(ip)) a.SetTag("appsec.client_ip", ip);
        if (d.Action == "allow") return;
        a.SetTag("appsec.event", true);
        a.SetTag("appsec.rule_id", d.RuleId ?? "");
        a.SetTag("appsec.category", d.Category ?? "");
        a.SetTag("appsec.blocked", d.Action == "block");
    }

    /// <summary>Mark the current request as a login attempt; failed ones feed the account-takeover rules.</summary>
    public static void TrackLogin(string login, bool success)
    {
        var a = Activity.Current;
        if (a is null) return;
        a.SetTag("appsec.login", login);
        a.SetTag("appsec.login.success", success);
        if (success) a.SetTag("appsec.auth", true);
    }

    /// <summary>Add the WAF middleware; <paramref name="user"/> names the caller from the request when known.</summary>
    public static IApplicationBuilder UseWatchtowerAppsec(this IApplicationBuilder app, Func<HttpContext, string?>? user = null)
        => app.Use(async (ctx, next) =>
        {
            if (!Active)
            {
                await next();
                return;
            }
            var req = FromRequest(ctx.Request, user?.Invoke(ctx));
            var d = Inspect(req);
            Annotate(d, req["ip"]);
            if (d.Action != "block")
            {
                await next();
                return;
            }
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            ctx.Response.ContentType = "application/problem+json";
            await ctx.Response.WriteAsync(Problem);
        });

    /// <summary>One poll: the new ETag, or null when the ruleset is unchanged or the fetch failed.</summary>
    public static async Task<string?> PollAsync(HttpClient http, string endpoint, string key, string service, string etag, CancellationToken ct = default)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{endpoint.TrimEnd('/')}/v1/appsec/ruleset?service={Uri.EscapeDataString(service)}");
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {key}");
            if (etag.Length > 0) req.Headers.TryAddWithoutValidation("If-None-Match", etag);
            using var res = await http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode || res.StatusCode == System.Net.HttpStatusCode.NotModified) return null;
            var body = await res.Content.ReadAsStringAsync(ct);
            if (body.Length > 4 << 20) return null;
            using var doc = JsonDocument.Parse(body);
            SetRuleset(doc.RootElement.Clone());
            return res.Headers.ETag?.Tag ?? "";
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or TaskCanceledException)
        {
            return null;
        }
    }

    /// <summary>Fetch the ruleset now and keep polling every 30 seconds in the background.</summary>
    public static void Start(string endpoint, string key, string service)
    {
        Stop();
        var cts = _poller = new CancellationTokenSource();
        _ = Task.Run(async () =>
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var etag = "";
            while (!cts.IsCancellationRequested)
            {
                etag = await PollAsync(http, endpoint, key, service, etag, cts.Token) ?? etag;
                try { await Task.Delay(TimeSpan.FromSeconds(30), cts.Token); }
                catch (TaskCanceledException) { return; }
            }
        });
    }

    public static void Stop()
    {
        _poller?.Cancel();
        _poller = null;
        SetRuleset(null);
    }
}
