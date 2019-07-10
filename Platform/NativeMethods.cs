using System;
using System.Runtime.InteropServices;

internal static class NativeMethods
{
    // Import the libargon2 shared library
    [DllImport("libargon2", CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int argon2id_hash_raw(UInt32 time_cost, UInt32 mem_cost, UInt32 parallelism,
                             IntPtr data, UIntPtr data_len,
                             IntPtr salt, UIntPtr salt_len,
                             IntPtr output, UIntPtr output_len);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    internal static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll")]
    internal static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    [DllImport("Kernel32")]
    internal static extern bool SetConsoleCtrlHandler(HandlerRoutine Handler, bool Add);

    internal enum CtrlTypes
    {
        CTRL_C_EVENT = 0,
        CTRL_BREAK_EVENT,
        CTRL_CLOSE_EVENT,
        CTRL_LOGOFF_EVENT = 5,
        CTRL_SHUTDOWN_EVENT
    }
    internal delegate bool HandlerRoutine(CtrlTypes CtrlType);
}

