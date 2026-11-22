using System.Buffers.Binary;
using System.Text;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Watchtower.Sdk.Tests")]

namespace Watchtower.Profiling;

/// <summary>
/// Reader of the EventPipe "nettrace" format (V4+, as .NET Core 3.0 and later write it) that keeps
/// only what a sampling profile needs: SampleProfiler ThreadSample events with their stacks, and
/// the method address ranges of MethodLoadVerbose / rundown MethodDCEndVerbose events, then folds
/// the stacks into <c>root;...;leaf</c> counts.
/// </summary>
internal sealed class NetTrace
{
    internal const string SampleProvider = "Microsoft-DotNETCore-SampleProfiler";
    internal const string RuntimeProvider = "Microsoft-Windows-DotNETRuntime";
    internal const string RundownProvider = "Microsoft-Windows-DotNETRuntimeRundown";
    private const int MaxFrames = 256;

    private readonly byte[] _b;
    private int _ptr = 8;
    private readonly Dictionary<int, (string Provider, int Id)> _meta = new();
    private readonly Dictionary<int, ulong[]> _stacks = new();
    private readonly Dictionary<string, (ulong[] Ips, string Prefix, long N)> _samples = new();
    private readonly IReadOnlyList<SpanInterval> _spans;
    private readonly List<(ulong Start, uint Size, string Name)> _methods = new();

    private NetTrace(byte[] b, IReadOnlyList<SpanInterval> spans)
    {
        _b = b;
        _spans = spans;
    }

    /// <summary>Folded stacks (root first) with their sample counts.</summary>
    internal static Dictionary<string, long> Fold(byte[] nettrace, IReadOnlyList<SpanInterval>? spans = null)
    {
        var t = new NetTrace(nettrace, spans ?? Array.Empty<SpanInterval>());
        t.Parse();
        return t.Folded();
    }

    private InvalidDataException Bad(string what) => new($"nettrace: {what} at byte {_ptr}");

    private int I32(int at) => BinaryPrimitives.ReadInt32LittleEndian(_b.AsSpan(at, 4));

    private void Expect(byte tag)
    {
        if (_ptr >= _b.Length || _b[_ptr++] != tag) throw Bad($"expected tag {tag}");
    }

    private void Parse()
    {
        if (_b.Length < 8 || Encoding.ASCII.GetString(_b, 0, 8) != "Nettrace") throw Bad("no Nettrace magic");
        _ptr += 4 + I32(_ptr); // "!FastSerialization.1"
        while (_ptr < _b.Length)
        {
            if (_b[_ptr] == 1) return; // NullReference: end of stream
            Expect(5); // BeginPrivateObject
            Expect(5); // its type
            Expect(1);
            _ptr += 8; // version, minimum reader version
            int n = I32(_ptr);
            string type = Encoding.ASCII.GetString(_b, _ptr + 4, n);
            _ptr += 4 + n;
            Expect(6);
            if (type == "Trace")
            {
                _ptr += 16 + 8 + 8 + 4 * 4; // start time, QPC sync and frequency, pointer size, pid, cpus, rate
            }
            else
            {
                int size = I32(_ptr);
                _ptr = (_ptr + 4 + 3) & ~3; // blocks are 4-byte aligned in the stream
                if (size < 0 || _ptr + size > _b.Length) throw Bad("block past the end");
                Block(type, _ptr, _ptr + size);
                _ptr += size;
            }
            Expect(6); // EndObject
        }
    }

    private void Block(string type, int p, int end)
    {
        switch (type)
        {
            case "StackBlock":
                int id = I32(p), count = I32(p + 4);
                p += 8;
                for (int i = 0; i < count && p + 4 <= end; i++, id++)
                {
                    int sz = I32(p);
                    var ips = new ulong[Math.Min(sz / 8, MaxFrames)];
                    for (int k = 0; k < ips.Length; k++) ips[k] = BinaryPrimitives.ReadUInt64LittleEndian(_b.AsSpan(p + 4 + 8 * k));
                    _stacks[id] = ips;
                    p += 4 + sz;
                }
                break;
            case "EventBlock":
            case "MetadataBlock":
                Events(p, end, type == "MetadataBlock");
                break;
            case "SPBlock":
                _stacks.Clear(); // stack ids do not outlive a sequence point
                break;
        }
    }

    private uint VarU32(ref int p) => (uint)VarU64(ref p);

    private ulong VarU64(ref int p)
    {
        ulong v = 0;
        for (int shift = 0; shift < 64; shift += 7)
        {
            byte x = _b[p++];
            v |= (ulong)(x & 0x7f) << shift;
            if ((x & 0x80) == 0) return v;
        }
        throw Bad("varint too long");
    }

    private void Events(int p, int end, bool metadata)
    {
        int headerSize = BinaryPrimitives.ReadUInt16LittleEndian(_b.AsSpan(p));
        bool compressed = (BinaryPrimitives.ReadUInt16LittleEndian(_b.AsSpan(p + 2)) & 1) != 0;
        p += headerSize;
        if (!compressed)
        {
            UncompressedEvents(p, end, metadata);
            return;
        }
        int metaId = 0, stackId = 0, len = 0;
        long thread = 0, time = 0;
        while (p < end)
        {
            byte f = _b[p++];
            if ((f & 1) != 0) metaId = (int)VarU32(ref p);
            if ((f & 2) != 0) { VarU32(ref p); VarU64(ref p); VarU32(ref p); } // sequence, capture thread, cpu
            if ((f & 4) != 0) thread = (long)VarU64(ref p);
            if ((f & 8) != 0) stackId = (int)VarU32(ref p);
            time += (long)VarU64(ref p);
            if ((f & 16) != 0) p += 16; // activity id
            if ((f & 32) != 0) p += 16; // related activity id
            if ((f & 128) != 0) len = (int)VarU32(ref p);
            if (len < 0 || p + len > end) throw Bad("event past its block");
            if (metadata) Metadata(p, len);
            else Event(metaId, stackId, p, len, thread, time);
            p += len;
        }
    }

    /// <summary>
    /// Events with full headers (nettrace V4, written when header compression is off): EventSize,
    /// then MetadataId (high bit IsSorted), SequenceNumber, ThreadId, CaptureThreadId,
    /// ProcessorNumber, StackId, TimeStamp, ActivityID, RelatedActivityID and PayloadSize, then the
    /// payload, padded to a 4-byte file offset (NetTraceFormat_v5.md, "Uncompressed events").
    /// </summary>
    private void UncompressedEvents(int p, int end, bool metadata)
    {
        const int header = 76; // after EventSize
        while (p + 4 <= end)
        {
            int size = I32(p), at = p + 4;
            if (size < header || at + size > end) throw Bad("event past its block");
            int metaId = I32(at) & 0x7fffffff;
            long thread = BinaryPrimitives.ReadInt64LittleEndian(_b.AsSpan(at + 8));
            int stackId = I32(at + 28);
            long time = BinaryPrimitives.ReadInt64LittleEndian(_b.AsSpan(at + 32));
            int len = I32(at + 72);
            if (len < 0 || len > size - header) throw Bad("event past its block");
            if (metadata) Metadata(at + header, len);
            else Event(metaId, stackId, at + header, len, thread, time);
            p = (at + size + 3) & ~3;
        }
    }

    private string Utf16z(ref int p, int end)
    {
        int start = p;
        while (p + 1 < end && (_b[p] != 0 || _b[p + 1] != 0)) p += 2;
        var s = Encoding.Unicode.GetString(_b, start, p - start);
        p += 2;
        return s;
    }

    private void Metadata(int p, int len)
    {
        int end = p + len, id = I32(p);
        p += 4;
        string provider = Utf16z(ref p, end);
        if (p + 4 <= end) _meta[id] = (provider, I32(p));
    }

    private string PrefixAt(long thread, long time)
    {
        for (int i = _spans.Count - 1; i >= 0; i--)
        {
            var s = _spans[i];
            if (s.Thread == thread && s.Start <= time && (s.End == 0 || time <= s.End)) return s.Prefix;
        }
        return "";
    }

    private void Event(int metaId, int stackId, int p, int len, long thread, long time)
    {
        if (!_meta.TryGetValue(metaId, out var m)) return;
        if (m.Provider == SampleProvider && m.Id == 0)
        {
            if (!_stacks.TryGetValue(stackId, out var ips) || ips.Length == 0) return;
            string prefix = PrefixAt(thread, time);
            string key = prefix + string.Join(',', ips);
            _samples[key] = (ips, prefix, (_samples.TryGetValue(key, out var c) ? c.N : 0) + 1);
        }
        else if ((m.Provider == RuntimeProvider || m.Provider == RundownProvider) && (m.Id == 143 || m.Id == 144) && len >= 36)
        {
            // MethodID, ModuleID, MethodStartAddress, MethodSize, MethodToken, MethodFlags, Namespace, Name
            ulong start = BinaryPrimitives.ReadUInt64LittleEndian(_b.AsSpan(p + 16));
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(_b.AsSpan(p + 24));
            int q = p + 36, end = p + len;
            string ns = Utf16z(ref q, end), name = Utf16z(ref q, end);
            _methods.Add((start, size, ns.Length > 0 ? $"{ns}.{name}" : name));
        }
    }

    private string? Resolve(ulong ip)
    {
        int lo = 0, hi = _methods.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            var m = _methods[mid];
            if (ip < m.Start) hi = mid - 1;
            else if (ip >= m.Start + m.Size) lo = mid + 1;
            else return m.Name;
        }
        return null;
    }

    private Dictionary<string, long> Folded()
    {
        _methods.Sort((a, b) => a.Start.CompareTo(b.Start));
        var out_ = new Dictionary<string, long>();
        var frames = new List<string>();
        foreach (var (ips, prefix, n) in _samples.Values)
        {
            frames.Clear();
            for (int i = ips.Length - 1; i >= 0; i--) // leaf first in the trace, root first in folded
            {
                // a return address points past its call
                string name = (Resolve(i == 0 ? ips[i] : ips[i] - 1) ?? "[native]").Replace(';', ':');
                if (name == "[native]" && frames.Count > 0 && frames[^1] == name) continue;
                frames.Add(name);
            }
            string key = prefix + string.Join(';', frames);
            out_[key] = (out_.TryGetValue(key, out var c) ? c : 0) + n;
        }
        return out_;
    }
}
