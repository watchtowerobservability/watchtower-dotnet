using Watchtower;
using Xunit;

public class InitTests
{
    private const string Key = "wtk_example_not_a_real_key"; // fake

    [Fact]
    public void ExportsWithKeyHeader()
    {
        var c = new Config("svc", key: Key);
        Assert.Equal($"authorization=Bearer {Key}", c.Headers);
        Assert.Equal("http://localhost:4318", c.Endpoint);
        Assert.DoesNotContain(Key, c.ToString());
    }

    [Fact]
    public void WtAttributesDropped()
    {
        var c = new Config("svc", "https://x.example/", resource: new Dictionary<string, object>
        {
            ["wt.project_id"] = "p",
            ["env"] = "prod",
        });
        var a = c.ResourceAttributes();
        Assert.Equal(2, a.Count);
        Assert.False(a.ContainsKey("wt.project_id"));
        Assert.Equal("https://x.example", c.Endpoint);
    }

    [Fact]
    public void RedactionHookMasksAndDrops()
    {
        var attrs = new Dictionary<string, object?> { ["password"] = "x", ["email"] = "a@b.c", ["wt.t"] = "t" };
        var o = Redaction.Apply(attrs, (k, v) => k == "password" ? null : k == "email" ? "[redacted]" : v);
        Assert.Equal("[redacted]", Assert.Single(o).Value);
    }

    [Fact]
    public void BufferDropsOldest()
    {
        var b = new OfflineBuffer<int>(2);
        b.Push(1); b.Push(2); b.Push(3);
        Assert.Equal(new[] { 2, 3 }, b.Drain());
    }
}
