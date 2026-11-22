using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Watchtower.Sdk.Tests;

[Collection("appsec")]
public class AppsecTests : IDisposable
{
    private static JsonElement Rules(string mode) => JsonDocument.Parse(
        "{\"mode\":\"" + mode + "\",\"rules\":[" +
        "{\"id\":\"sqli\",\"category\":\"injection\",\"pattern\":\"union\\\\s+select|' or 1=1\",\"fields\":[\"path\",\"query\"]}," +
        "{\"id\":\"bad\",\"category\":\"x\",\"pattern\":\"(\",\"fields\":[\"path\"]}]," +
        "\"denylist\":{\"ip\":[{\"value\":\"203.0.113.9\",\"expires_at\":4102444800}],\"user\":[{\"value\":\"mallory\"}]}}").RootElement.Clone();

    public AppsecTests() => Appsec.SetRuleset(Rules("block"));

    public void Dispose() => Appsec.Stop();

    private static HttpContext Ctx(string query, string? xff = null)
    {
        var c = new DefaultHttpContext();
        c.Request.Path = "/items";
        c.Request.QueryString = new QueryString("?" + query);
        c.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        if (xff != null) c.Request.Headers["X-Forwarded-For"] = xff;
        return c;
    }

    [Fact]
    public void A_percent_encoded_injection_is_blocked_and_a_clean_request_passes()
    {
        var d = Appsec.Inspect(Appsec.FromRequest(Ctx("q=1%27%20OR%201%3D1").Request));
        Assert.Equal(("block", "sqli"), (d.Action, d.RuleId));
        Assert.Equal("allow", Appsec.Inspect(Appsec.FromRequest(Ctx("q=shoes").Request)).Action);
    }

    [Fact]
    public void Monitor_mode_flags_and_the_denylist_always_blocks()
    {
        Appsec.SetRuleset(Rules("monitor"));
        Assert.Equal("monitor", Appsec.Inspect(Appsec.FromRequest(Ctx("q=1+union+select+1").Request)).Action);
        var d = Appsec.Inspect(Appsec.FromRequest(Ctx("q=ok", "203.0.113.9").Request));
        Assert.Equal(("block", "denylist"), (d.Action, d.RuleId));
        Assert.True(Appsec.UserBlocked("mallory"));
    }

    [Fact]
    public void A_runaway_pattern_is_no_match_not_a_hang()
    {
        Appsec.SetRuleset(JsonDocument.Parse("{\"mode\":\"block\",\"rules\":[{\"id\":\"boom\",\"category\":\"x\",\"pattern\":\"(a+)+$\",\"fields\":[\"query\"]}]}").RootElement.Clone());
        var d = Appsec.Inspect(new Dictionary<string, string> { ["query"] = new string('a', 40) + "!" });
        Assert.Equal("allow", d.Action);
    }
}
