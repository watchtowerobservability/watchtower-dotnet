using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net.Sockets;
using System.Text;

namespace Watchtower.Profiling;

/// <summary>
/// Client of the runtime's own diagnostics server (the documented "Diagnostics IPC" protocol),
/// written here instead of taking Microsoft.Diagnostics.NETCore.Client: it starts and stops an
/// EventPipe session on a process (usually this one) and hands back the nettrace stream.
/// </summary>
internal static class DiagnosticsIpc
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("DOTNET_IPC_V1\0");
    private const byte EventPipe = 0x02, StopTracing = 0x01, CollectTracing2 = 0x03;

    internal readonly record struct Provider(string Name, ulong Keywords, uint Level);

    internal static Stream Connect(int pid)
    {
        if (OperatingSystem.IsWindows())
        {
            var pipe = new NamedPipeClientStream(".", $"dotnet-diagnostic-{pid}", PipeDirection.InOut);
            pipe.Connect(3000);
            return pipe;
        }
        var path = Directory.GetFiles(Path.GetTempPath(), $"dotnet-diagnostic-{pid}-*-socket").FirstOrDefault()
            ?? throw new IOException("the diagnostics server is off (DOTNET_EnableDiagnostics=0?)");
        var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        s.Connect(new UnixDomainSocketEndPoint(path));
        return new NetworkStream(s, ownsSocket: true);
    }

    internal static byte[] Frame(byte set, byte id, byte[] payload)
    {
        var b = new byte[20 + payload.Length];
        Magic.CopyTo(b, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(14), (ushort)b.Length);
        b[16] = set;
        b[17] = id;
        payload.CopyTo(b, 20);
        return b;
    }

    internal static byte[] CollectPayload(IEnumerable<Provider> providers, uint bufferMb)
    {
        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms, Encoding.Unicode);
        w.Write(bufferMb);
        w.Write(1u); // format: nettrace
        w.Write((byte)1); // rundown at stop: method names for the sampled addresses
        var list = providers.ToList();
        w.Write((uint)list.Count);
        foreach (var p in list)
        {
            w.Write(p.Keywords);
            w.Write(p.Level);
            w.Write((uint)(p.Name.Length + 1));
            w.Write(Encoding.Unicode.GetBytes(p.Name + "\0"));
            w.Write(0u); // no filter data
        }
        w.Flush();
        return ms.ToArray();
    }

    /// <summary>Reads one response; returns its payload or throws on an error answer.</summary>
    internal static byte[] Response(Stream s)
    {
        var h = new byte[20];
        s.ReadExactly(h);
        if (!h.AsSpan(0, 14).SequenceEqual(Magic)) throw new IOException("not a diagnostics IPC answer");
        var payload = new byte[BinaryPrimitives.ReadUInt16LittleEndian(h.AsSpan(14)) - 20];
        s.ReadExactly(payload);
        if (h[17] != 0)
            throw new IOException($"diagnostics server error 0x{(payload.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(payload) : 0):x8}");
        return payload;
    }

    /// <summary>Starts a session; the returned stream carries nettrace until the session stops.</summary>
    internal static (Stream Trace, ulong Session) Start(int pid, IEnumerable<Provider> providers, uint bufferMb = 64)
    {
        var s = Connect(pid);
        try
        {
            s.Write(Frame(EventPipe, CollectTracing2, CollectPayload(providers, bufferMb)));
            return (s, BinaryPrimitives.ReadUInt64LittleEndian(Response(s)));
        }
        catch
        {
            s.Dispose();
            throw;
        }
    }

    internal static void Stop(int pid, ulong session)
    {
        using var s = Connect(pid);
        var p = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(p, session);
        s.Write(Frame(EventPipe, StopTracing, p));
        Response(s);
    }
}
