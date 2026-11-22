using System.Globalization;
using System.Text.RegularExpressions;

namespace Watchtower.Probes;

/// <summary>
/// The probe condition subset shared by every Watchtower agent: comparisons, <c>in</c>,
/// <c>contains</c>, <c>&amp;&amp; || !</c> and parentheses over dotted local names. There are no
/// calls, so evaluating a condition cannot run code. Values are the plain snapshot values
/// (string, long, double, bool, null, List, Dictionary).
/// </summary>
public sealed class Condition
{
    private static readonly Regex Token = new(
        @"\G\s*(&&|\|\||==|!=|<=|>=|[<>!()\[\],]|'[^']*'|""[^""]*""|-?\d+(?:\.\d+)?|[A-Za-z_][\w.]*)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private delegate object? Node(IReadOnlyDictionary<string, object?> v);

    private readonly List<string> _t = new();
    private int _i;

    private Condition(string src)
    {
        var s = src.TrimEnd();
        var pos = 0;
        while (pos < s.Length)
        {
            var m = Token.Match(s, pos);
            if (!m.Success) throw new ArgumentException("bad condition");
            _t.Add(m.Groups[1].Value);
            pos = m.Index + m.Length;
        }
    }

    /// <summary>Compiles src; throws ArgumentException outside the subset (calls included).</summary>
    public static Func<IReadOnlyDictionary<string, object?>, bool> Compile(string? src)
    {
        if (string.IsNullOrWhiteSpace(src)) return _ => true;
        var c = new Condition(src);
        var root = c.Or();
        if (c._i != c._t.Count) throw new ArgumentException("bad condition");
        return v => Truthy(root(v));
    }

    private string? Peek() => _i < _t.Count ? _t[_i] : null;

    private bool Eat(string s)
    {
        if (Peek() != s) return false;
        _i++;
        return true;
    }

    private static object? Lit(string x) => x switch
    {
        "true" => true,
        "false" => false,
        "null" => null,
        _ when x.StartsWith('\'') || x.StartsWith('"') => x[1..^1],
        _ when x.Contains('.') => double.Parse(x, CultureInfo.InvariantCulture),
        _ => long.Parse(x, CultureInfo.InvariantCulture),
    };

    internal static object? Get(IReadOnlyDictionary<string, object?> v, string name)
    {
        object? o = v;
        foreach (var k in name.Split('.'))
            o = o is IReadOnlyDictionary<string, object?> d && d.TryGetValue(k, out var x) ? x
              : o is Dictionary<string, object?> d2 && d2.TryGetValue(k, out var y) ? y : null;
        return o;
    }

    private Node Atom()
    {
        var x = Peek() ?? throw new ArgumentException("bad condition");
        _i++;
        if (x == "(")
        {
            var e = Or();
            if (!Eat(")")) throw new ArgumentException("bad condition");
            return e;
        }
        if (x == "[")
        {
            var items = new List<object?>();
            while (Peek() != "]")
            {
                var n = Peek() ?? throw new ArgumentException("bad condition");
                _i++;
                if (n != ",") items.Add(Lit(n));
            }
            _i++;
            return _ => items;
        }
        if (x[0] is '\'' or '"' or '-' || char.IsDigit(x[0]) || x is "true" or "false" or "null")
        {
            var val = Lit(x);
            return _ => val;
        }
        if (Peek() == "(") throw new ArgumentException("function calls are not allowed");
        return v => Get(v, x);
    }

    private static bool Truthy(object? o) => o is not null && !(o is bool b && !b);

    private static object? Num(object? o) => o is long or int or double ? Convert.ToDouble(o, CultureInfo.InvariantCulture) : o;

    internal static bool Compare(string op, object? x, object? y)
    {
        object? a = Num(x), b = Num(y);
        switch (op)
        {
            case "==": return Equals(a, b);
            case "!=": return !Equals(a, b);
            case "in": return y is List<object?> l && l.Any(e => Equals(Num(e), a));
            case "contains": return x is string s && y is string t && s.Contains(t, StringComparison.Ordinal);
        }
        int c;
        if (a is double da && b is double db) c = da.CompareTo(db);
        else if (a is string sa && b is string sb) c = string.CompareOrdinal(sa, sb);
        else return false;
        return op switch { "<" => c < 0, "<=" => c <= 0, ">" => c > 0, _ => c >= 0 };
    }

    private Node Cmp()
    {
        var a = Atom();
        foreach (var op in new[] { "==", "!=", "<=", ">=", "<", ">", "in", "contains" })
        {
            if (!Eat(op)) continue;
            var b = Atom();
            return v => Compare(op, a(v), b(v));
        }
        return a;
    }

    private Node Not()
    {
        if (!Eat("!")) return Cmp();
        var n = Not();
        return v => !Truthy(n(v));
    }

    private Node And()
    {
        var l = Not();
        while (Eat("&&"))
        {
            var a = l;
            var r = Not();
            l = v => Truthy(a(v)) && Truthy(r(v));
        }
        return l;
    }

    private Node Or()
    {
        var l = And();
        while (Eat("||"))
        {
            var a = l;
            var r = And();
            l = v => Truthy(a(v)) || Truthy(r(v));
        }
        return l;
    }
}
