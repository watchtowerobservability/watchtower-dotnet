using System.Runtime.InteropServices;

namespace Watchtower.Profiling;

/// <summary>A span's time on an OS thread, on the clock of EventPipe timestamps (Stopwatch).</summary>
internal sealed class SpanInterval(long thread, long start, string prefix)
{
    internal long Thread { get; } = thread;
    internal long Start { get; } = start;
    internal string Prefix { get; } = prefix;
    internal long End; // 0 while open
}

/// <summary>The OS thread id EventPipe events carry.</summary>
internal static class OsThread
{
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("libc", EntryPoint = "syscall")]
    private static extern long Syscall(long number);

    [DllImport("libc")]
    private static extern int pthread_threadid_np(nint thread, out ulong id);

    private static long LinuxGetTid() => Syscall(RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 178 : 186);

    internal static long Id()
    {
        if (OperatingSystem.IsWindows()) return GetCurrentThreadId();
        if (OperatingSystem.IsLinux()) return LinuxGetTid();
        return pthread_threadid_np(0, out var id) == 0 ? (long)id : 0;
    }
}
