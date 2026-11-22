using System.Runtime.CompilerServices;
using System.Text;
using Watchtower.Profiling;
using Xunit;

public class ProfilerTests
{
    private const string Key = "wtk_example_not_a_real_key"; // fake

    private static void VarU(List<byte> b, ulong v)
    {
        do { byte x = (byte)(v & 0x7f); v >>= 7; b.Add(v != 0 ? (byte)(x | 0x80) : x); } while (v != 0);
    }

    private static byte[] U16z(string s) => Encoding.Unicode.GetBytes(s + "\0");

    // One event (compressed header unless told otherwise): metadata id, stack id, payload.
    private static void Ev(List<byte> b, int meta, int stack, byte[] payload, bool compressed = true)
    {
        if (!compressed) // full header; the list starts 4-aligned in the file
        {
            b.AddRange(BitConverter.GetBytes(76 + payload.Length));
            b.AddRange(BitConverter.GetBytes(meta));
            b.AddRange(new byte[4]); // sequence number
            b.AddRange(BitConverter.GetBytes(7L)); // thread
            b.AddRange(new byte[12]); // capture thread, processor
            b.AddRange(BitConverter.GetBytes(stack));
            b.AddRange(new byte[40]); // timestamp, activity ids
            b.AddRange(BitConverter.GetBytes(payload.Length));
            b.AddRange(payload);
            while (b.Count % 4 != 0) b.Add(0);
            return;
        }
        b.Add(1 | 8 | 128);
        VarU(b, (ulong)meta);
        VarU(b, (ulong)stack);
        VarU(b, 0); // timestamp delta
        VarU(b, (ulong)payload.Length);
        b.AddRange(payload);
    }

    private static void Obj(List<byte> s, string type, byte[]? block, byte[]? raw = null)
    {
        s.AddRange(new byte[] { 5, 5, 1 });
        s.AddRange(BitConverter.GetBytes(2));
        s.AddRange(BitConverter.GetBytes(2));
        s.AddRange(BitConverter.GetBytes(type.Length));
        s.AddRange(Encoding.ASCII.GetBytes(type));
        s.Add(6);
        if (raw != null) s.AddRange(raw);
        else
        {
            s.AddRange(BitConverter.GetBytes(block!.Length));
            while (s.Count % 4 != 0) s.Add(0);
            s.AddRange(block);
        }
        s.Add(6);
    }

    private static byte[] EventBlock(List<byte> events, bool compressed = true)
    {
        var h = new List<byte>(BitConverter.GetBytes((ushort)20));
        h.AddRange(BitConverter.GetBytes((ushort)(compressed ? 1 : 0)));
        h.AddRange(new byte[16]);
        h.AddRange(events);
        return h.ToArray();
    }

    private static byte[] Method(ulong start, uint size, string ns, string name) =>
        new byte[16].Concat(BitConverter.GetBytes(start)).Concat(BitConverter.GetBytes(size)).Concat(new byte[8])
            .Concat(U16z(ns)).Concat(U16z(name)).Concat(U16z("void ()")).Concat(new byte[2]).ToArray();

    internal static byte[] Synthetic(bool compressed = true)
    {
        var s = new List<byte>(Encoding.ASCII.GetBytes("Nettrace"));
        s.AddRange(BitConverter.GetBytes(20));
        s.AddRange(Encoding.ASCII.GetBytes("!FastSerialization.1"));
        Obj(s, "Trace", null, new byte[48]);
        var meta = new List<byte>();
        Ev(meta, 0, 0, BitConverter.GetBytes(1).Concat(U16z(NetTrace.SampleProvider)).Concat(BitConverter.GetBytes(0)).ToArray(), compressed);
        Ev(meta, 0, 0, BitConverter.GetBytes(2).Concat(U16z(NetTrace.RundownProvider)).Concat(BitConverter.GetBytes(144)).ToArray(), compressed);
        Obj(s, "MetadataBlock", EventBlock(meta, compressed));
        var stacks = new List<byte>(BitConverter.GetBytes(1));
        stacks.AddRange(BitConverter.GetBytes(2));
        foreach (var ips in new[] { new ulong[] { 0x1010, 0x2005 }, new ulong[] { 0x9000, 0x2005 } })
        {
            stacks.AddRange(BitConverter.GetBytes(ips.Length * 8));
            foreach (var ip in ips) stacks.AddRange(BitConverter.GetBytes(ip));
        }
        Obj(s, "StackBlock", stacks.ToArray());
        var ev = new List<byte>();
        Ev(ev, 1, 1, BitConverter.GetBytes(1), compressed);
        Ev(ev, 1, 1, BitConverter.GetBytes(1), compressed);
        Ev(ev, 1, 2, BitConverter.GetBytes(2), compressed);
        Ev(ev, 2, 0, Method(0x1000, 0x100, "App.Program", "Leaf"), compressed);
        Ev(ev, 2, 0, Method(0x2000, 0x100, "App.Program", "Main"), compressed);
        Obj(s, "EventBlock", EventBlock(ev, compressed));
        s.Add(1);
        return s.ToArray();
    }

    [Fact]
    public void FoldsSyntheticNettrace()
    {
        var f = NetTrace.Fold(Synthetic());
        Assert.Equal(2, f["App.Program.Main;App.Program.Leaf"]);
        Assert.Equal(1, f["App.Program.Main;[native]"]);
        Assert.Equal(f, NetTrace.Fold(Synthetic(compressed: false))); // full event headers
        Assert.Throws<InvalidDataException>(() => NetTrace.Fold(Encoding.ASCII.GetBytes("NotTrace")));
    }

    [Fact]
    public void UriAndBodyAndFailedUpload()
    {
        using var p = new Profiler(Key, "http://127.0.0.1:9/", "api", new Dictionary<string, string> { ["env"] = "prod" });
        Assert.StartsWith("http://127.0.0.1:9/ingest?name=api.wall%7Benv%3Dprod%7D&from=1&until=2&format=folded", p.IngestUri(1, 2).AbsoluteUri);
        Assert.DoesNotContain(Key, p.ToString());
        Assert.Equal("a;b 3\n", Profiler.Body(new Dictionary<string, long> { ["a;b"] = 3 }));
        p.Upload(new Dictionary<string, long> { ["a"] = 1 }, 1, 2);
        Assert.Equal(1, p.Dropped);
        Assert.Throws<ArgumentException>(() => new Profiler(""));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void BusyWatchtowerMarker(CancellationToken ct)
    {
        double x = 0;
        while (!ct.IsCancellationRequested) x += Math.Sqrt(x + 1);
        GC.KeepAlive(x);
    }

    [Fact]
    public void LabelsSamplesInsideASpan()
    {
        if (Environment.GetEnvironmentVariable("DOTNET_EnableDiagnostics") == "0") return;
        using var cts = new CancellationTokenSource();
        var t = new Thread(() => Profiler.WithSpan(() => { BusyWatchtowerMarker(cts.Token); return 0; }, "ab", "cd")) { IsBackground = true };
        t.Start();
        Thread.Sleep(100);
        try
        {
            var f = Profiler.Capture(TimeSpan.FromSeconds(1));
            Assert.Contains(f.Keys, k => k.StartsWith("span_id=ab,trace_id=cd\t") && k.Contains("BusyWatchtowerMarker"));
        }
        finally
        {
            cts.Cancel();
            t.Join();
        }
    }

    [Fact]
    public void LabelsSamplesAfterAnAwait()
    {
        if (Environment.GetEnvironmentVariable("DOTNET_EnableDiagnostics") == "0") return;
        using var cts = new CancellationTokenSource();
        Profiler.AsyncSpanLabels = true;
        var task = Profiler.WithSpan(async () =>
        {
            await Task.Yield(); // resumes on another thread, with the span's ExecutionContext
            BusyWatchtowerMarker(cts.Token);
        }, "ef", "01");
        Thread.Sleep(100);
        try
        {
            var f = Profiler.Capture(TimeSpan.FromSeconds(1));
            Assert.Contains(f.Keys, k => k.StartsWith("span_id=ef,trace_id=01\t") && k.Contains("BusyWatchtowerMarker"));
        }
        finally
        {
            cts.Cancel();
            task.Wait();
            Profiler.AsyncSpanLabels = false;
        }
    }

    [Fact]
    public void CapturesThisProcess()
    {
        if (Environment.GetEnvironmentVariable("DOTNET_EnableDiagnostics") == "0") return;
        using var cts = new CancellationTokenSource();
        var t = new Thread(() => BusyWatchtowerMarker(cts.Token)) { IsBackground = true };
        t.Start();
        try
        {
            var f = Profiler.Capture(TimeSpan.FromSeconds(1));
            Assert.Contains(f.Keys, k => k.Contains("BusyWatchtowerMarker"));
        }
        finally
        {
            cts.Cancel();
        }
    }
}
