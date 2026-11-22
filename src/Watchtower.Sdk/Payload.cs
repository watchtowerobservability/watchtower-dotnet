using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Watchtower;

/// <summary>One payload capture rule as the edge serves it (APM-016).</summary>
public sealed record CaptureRule(string? Route, int BodyBytes, bool GraphqlQuery);

/// <summary>Payload and GraphQL capture driven by the capture rules set in Watchtower per service
/// and route (<c>GET /v1/capture-rules?service=</c>, an ingest key with scope <c>probes:read</c>).
/// Opt-in: nothing is fetched or recorded unless <c>WT_CAPTURE_RULES=1</c> and a rule matches the
/// route. Only text-like bodies are kept, at most the rule's <c>body_bytes</c> (hard cap 8 KiB),
/// after the default secret and PII detectors (a port of the pipeline's redact stage; ingest
/// applies the project's detectors again). The ASP.NET Core middleware records them.
/// shortcut: rules are fetched once at startup; poll with the ETag (poll_s) when live edits matter.</summary>
public static class PayloadCapture
{
    public const int HardMax = 8192;
    private const string R = "[REDACTED]";
    private const string SecretKeys = "password|passwd|secret|token|access_token|refresh_token|client_secret|api_?key|authorization";
    private static readonly Regex JsonSecret = new("(\"(?:" + SecretKeys + ")\"\\s*:\\s*)\"(?:[^\"\\\\]|\\\\.)*\"", RegexOptions.IgnoreCase);
    private static readonly Regex FormSecret = new("\\b((?:" + SecretKeys + ")=)[^&\\s]*", RegexOptions.IgnoreCase);
    private static readonly Regex[] Patterns =
    [
        new(@"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        new(@"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        new(@"bearer\s+[A-Za-z0-9._~+/-]+=*", RegexOptions.IgnoreCase),
        new(@"wt[ik]_[a-z0-9]{8}_[A-Za-z0-9_-]{43}"),
        new(@"(?:AKIA|ASIA)[0-9A-Z]{16}"),
        new(@"gh[pousr]_[A-Za-z0-9]{36,}"),
        new(@"[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
        new(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
        new(@"\b\d{3}-\d{2}-\d{4}\b"),
    ];
    private static readonly Regex Card = new(@"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b");
    private static readonly Regex Gql = new(@"(?:^|\})\s*(query|mutation|subscription)\b\s*([_A-Za-z][_0-9A-Za-z]*)?");
    private static readonly Regex Text = new("json|^text/|xml|x-www-form-urlencoded|graphql", RegexOptions.IgnoreCase);

    private static volatile IReadOnlyList<CaptureRule> _rules = [];

    public static IReadOnlyList<CaptureRule> Rules { get => _rules; set => _rules = value ?? []; }
    public static bool Active => _rules.Count > 0;

    /// <summary>Fetches the service's rules; any failure leaves capture off.</summary>
    public static async Task<IReadOnlyList<CaptureRule>> LoadAsync(HttpClient http, string apiUrl, string key, string service)
    {
        Rules = [];
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{apiUrl.TrimEnd('/')}/v1/capture-rules?service={Uri.EscapeDataString(service)}");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);
            using var res = await http.SendAsync(req).ConfigureAwait(false);
            if (!res.IsSuccessStatusCode) return Rules;
            using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync().ConfigureAwait(false));
            var list = new List<CaptureRule>();
            if (doc.RootElement.TryGetProperty("rules", out var rs) && rs.ValueKind == JsonValueKind.Array)
                foreach (var r in rs.EnumerateArray())
                    list.Add(new CaptureRule(
                        r.TryGetProperty("route", out var ro) && ro.ValueKind == JsonValueKind.String ? ro.GetString() : null,
                        r.TryGetProperty("body_bytes", out var b) && b.TryGetInt32(out var n) ? n : 0,
                        r.TryGetProperty("graphql_query", out var g) && g.ValueKind == JsonValueKind.True));
            Rules = list;
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or TaskCanceledException or InvalidOperationException)
        {
            Rules = [];
        }
        return Rules;
    }

    /// <summary><c>*</c> matches any run of characters (the edge's glob).</summary>
    public static bool Glob(string pat, string s) =>
        Regex.IsMatch(s, "^" + string.Join(".*", pat.Split('*').Select(Regex.Escape)) + "$", RegexOptions.Singleline);

    public static CaptureRule? RuleFor(string route) =>
        _rules.FirstOrDefault(r => string.IsNullOrEmpty(r.Route) || Glob(r.Route, route));

    private static bool Luhn(string s)
    {
        int sum = 0, n = 0;
        for (var i = s.Length - 1; i >= 0; i--)
        {
            if (!char.IsAsciiDigit(s[i])) continue;
            var x = s[i] - '0';
            if (n++ % 2 == 1) x = x * 2 > 9 ? x * 2 - 9 : x * 2;
            sum += x;
        }
        return n >= 13 && sum % 10 == 0;
    }

    /// <summary>Default secret and PII detectors: secret-named JSON and form fields, keys, tokens, emails, SSNs, Luhn-valid cards.</summary>
    public static string Redact(string s)
    {
        s = FormSecret.Replace(JsonSecret.Replace(s, "$1\"" + R + "\""), "$1" + R);
        foreach (var p in Patterns) s = p.Replace(s, R);
        return Card.Replace(s, m => Luhn(m.Value) ? R : m.Value);
    }

    private static string Cap(string s, int n)
    {
        var b = Encoding.UTF8.GetBytes(s);
        if (b.Length <= n) return s;
        return Encoding.UTF8.GetString(b, 0, n).TrimEnd('�');
    }

    /// <summary>Redacts a wider window than it keeps so a secret cut at the edge is still masked.</summary>
    public static string Excerpt(string s, int n) => Cap(Redact(Cap(s, n * 2)), n);

    /// <summary>Operation type and name of a GraphQL document (<c>{ ... }</c> is an anonymous query).</summary>
    public static (string Type, string? Name)? GraphqlOp(string doc)
    {
        var d = Regex.Replace(doc, "#[^\n]*", "");
        var m = Gql.Match(d);
        if (m.Success) return (m.Groups[1].Value, m.Groups[2].Success ? m.Groups[2].Value : null);
        return d.TrimStart().StartsWith('{') ? ("query", null) : null;
    }

    private static string? AsText(string? type, byte[]? body) =>
        body is { Length: > 0 } && (string.IsNullOrEmpty(type) || Text.IsMatch(type)) ? Encoding.UTF8.GetString(body) : null;

    /// <summary>Records the bodies and GraphQL operation the rule matching <paramref name="route"/> asks for; no rule, nothing.</summary>
    public static void Record(Activity? span, string route, string? reqType, byte[]? reqBody, string? resType, byte[]? resBody)
    {
        if (span is null || RuleFor(route) is not { } rule) return;
        var n = Math.Min(rule.BodyBytes, HardMax);
        var req = AsText(reqType, reqBody);
        var res = AsText(resType, resBody);
        if (n > 0 && req is not null) span.SetTag("http.request.body", Excerpt(req, n));
        if (n > 0 && res is not null) span.SetTag("http.response.body", Excerpt(res, n));
        string? doc = null, opName = null;
        if (req is not null && (reqType ?? "").Contains("graphql", StringComparison.OrdinalIgnoreCase)) doc = req;
        else if (req is not null)
        {
            try
            {
                using var j = JsonDocument.Parse(req);
                if (j.RootElement.ValueKind == JsonValueKind.Object && j.RootElement.TryGetProperty("query", out var q) && q.ValueKind == JsonValueKind.String)
                {
                    doc = q.GetString();
                    if (j.RootElement.TryGetProperty("operationName", out var on) && on.ValueKind == JsonValueKind.String) opName = on.GetString();
                }
            }
            catch (JsonException) { }
        }
        if (doc is null || GraphqlOp(doc) is not { } op) return;
        span.SetTag("graphql.operation.type", op.Type);
        if ((opName ?? op.Name) is { } name) span.SetTag("graphql.operation.name", name);
        if (rule.GraphqlQuery) span.SetTag("graphql.document", Excerpt(doc, HardMax));
    }
}

/// <summary>Write-through stream that keeps the first <c>2 * HardMax</c> bytes for payload capture.</summary>
internal sealed class TeeStream(Stream inner) : Stream
{
    private readonly MemoryStream _copy = new();
    public byte[] Captured => _copy.ToArray();
    private void Keep(ReadOnlySpan<byte> b)
    {
        var room = (2 * PayloadCapture.HardMax) - (int)_copy.Length;
        if (room > 0) _copy.Write(b[..Math.Min(room, b.Length)]);
    }
    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => inner.Length;
    public override long Position { get => inner.Position; set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) { Keep(buffer.AsSpan(offset, count)); inner.Write(buffer, offset, count); }
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        Keep(buffer.Span);
        await inner.WriteAsync(buffer, ct).ConfigureAwait(false);
    }
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
}
