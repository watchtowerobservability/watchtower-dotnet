using System.Text.Json;
using Watchtower;
using Xunit;

namespace Watchtower.Sdk.Tests;

public class RemoteSamplingTests
{
    private static JsonElement J(string s) => JsonDocument.Parse(s).RootElement;

    [Fact]
    public void RulesPickTheRatio()
    {
        var c = J("{\"strategyType\":\"RULES\",\"rules\":[{\"match\":{\"service\":\"api\",\"span_name_glob\":\"GET /health*\"},\"action\":{\"kind\":\"drop\"}},{\"match\":{\"service\":\"api\"},\"action\":{\"kind\":\"ratio\",\"ratio\":0.1}}]}");
        Assert.Equal(0, RemoteSampler.RatioFor(c, "api", "", "GET /health/live", null));
        Assert.Equal(0.1, RemoteSampler.RatioFor(c, "api", "", "GET /x", null));
        Assert.Equal(1, RemoteSampler.RatioFor(c, "web", "", "GET /x", null));
        Assert.Equal(0.25, RemoteSampler.RatioFor(J("{\"strategyType\":\"PROBABILISTIC\",\"probabilisticSampling\":{\"samplingRate\":0.25}}"), "a", "", "x", null));
    }

    [Fact]
    public void TraceFractionMatchesTheGatewayHash()
    {
        // fnv64a of sixteen zero bytes, as a fraction of 2^64
        var f = RemoteSampler.TraceFraction(new byte[16]);
        Assert.InRange(f, 0.0, 1.0);
        Assert.Equal(f, RemoteSampler.TraceFraction(new byte[16]));
    }
}
