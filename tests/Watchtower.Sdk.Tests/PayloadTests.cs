using System.Diagnostics;
using System.Text;
using Watchtower;
using Xunit;

public class PayloadTests
{
    [Fact]
    public void BodiesAreCappedRedactedAndRouteScoped()
    {
        PayloadCapture.Rules = [new CaptureRule("/api/*", 40, false)];
        try
        {
            using var a = new Activity("req").Start();
            var body = Encoding.UTF8.GetBytes("{\"user\":\"a@b.io\",\"password\":\"hunter2\",\"card\":\"4111 1111 1111 1111\"}");
            PayloadCapture.Record(a, "/api/login", "application/json", body, "image/png", [1, 2]);
            var got = (string)a.GetTagItem("http.request.body")!;
            Assert.True(Encoding.UTF8.GetByteCount(got) <= 40);
            Assert.DoesNotContain("hunter2", got);
            Assert.DoesNotContain("a@b.io", got);
            Assert.Null(a.GetTagItem("http.response.body"));
            using var other = new Activity("health").Start();
            PayloadCapture.Record(other, "/health", "text/plain", [65], null, null);
            Assert.Empty(other.TagObjects);
            Assert.Equal("4111 1111 1111 1112", PayloadCapture.Redact("4111 1111 1111 1112"));
        }
        finally { PayloadCapture.Rules = []; }
    }

    [Fact]
    public void GraphqlOperationAndDocument()
    {
        PayloadCapture.Rules = [new CaptureRule(null, 0, true)];
        try
        {
            using var a = new Activity("gql").Start();
            var q = "{\"query\":\"# c\\nmutation AddUser { add(email: \\\"x@y.io\\\") { id } }\"}";
            PayloadCapture.Record(a, "/graphql", "application/json", Encoding.UTF8.GetBytes(q), null, null);
            Assert.Equal("mutation", a.GetTagItem("graphql.operation.type"));
            Assert.Equal("AddUser", a.GetTagItem("graphql.operation.name"));
            Assert.DoesNotContain("x@y.io", (string)a.GetTagItem("graphql.document")!);
            Assert.Null(PayloadCapture.GraphqlOp("shoes"));
        }
        finally { PayloadCapture.Rules = []; }
    }
}
