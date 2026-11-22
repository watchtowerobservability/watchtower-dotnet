using System.Diagnostics;
using Watchtower;
using Xunit;

public sealed class LogCallerTests
{
    [Fact]
    public void FindReturnsTheCallingSourceFrame()
    {
        var c = LogCallerProcessor.Find(new StackTrace(true));
        Assert.NotNull(c);
        Assert.EndsWith("LogCallerTests.cs", c!.Value.File);
        Assert.True(c.Value.Line > 0);
    }
}
