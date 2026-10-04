param(
    [Parameter(Mandatory = $true)]
    [int]$ProcessId
)

$source = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class NativeThreadSampler
{
    const uint THREAD_SUSPEND_RESUME = 0x0002;
    const uint THREAD_GET_CONTEXT = 0x0008;
    const uint THREAD_QUERY_INFORMATION = 0x0040;
    const uint CONTEXT_CONTROL_INTEGER = 0x00100003;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint access, bool inheritHandle, uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SuspendThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr thread, IntPtr context);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    public static string[] Sample(int processId)
    {
        var rows = new List<string>();
        using (var process = Process.GetProcessById(processId))
        {
            foreach (ProcessThread threadInfo in process.Threads)
            {
                IntPtr thread = OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                    false,
                    (uint)threadInfo.Id);
                if (thread == IntPtr.Zero)
                    continue;

                IntPtr allocation = IntPtr.Zero;
                bool suspended = false;
                try
                {
                    uint previous = SuspendThread(thread);
                    if (previous == 0xFFFFFFFF)
                        continue;
                    suspended = true;

                    allocation = Marshal.AllocHGlobal(0x500);
                    long alignedValue = (allocation.ToInt64() + 15L) & ~15L;
                    IntPtr context = new IntPtr(alignedValue);
                    for (int offset = 0; offset < 0x4D0; offset += 8)
                        Marshal.WriteInt64(context, offset, 0L);
                    Marshal.WriteInt32(context, 48, unchecked((int)CONTEXT_CONTROL_INTEGER));

                    if (GetThreadContext(thread, context))
                    {
                        ulong rip = unchecked((ulong)Marshal.ReadInt64(context, 248));
                        ulong rsp = unchecked((ulong)Marshal.ReadInt64(context, 152));
                        rows.Add(String.Format(
                            "tid={0} cpu_ms={1:F0} rip=0x{2:X16} rsp=0x{3:X16}",
                            threadInfo.Id,
                            threadInfo.TotalProcessorTime.TotalMilliseconds,
                            rip,
                            rsp));
                    }
                }
                finally
                {
                    if (suspended)
                        ResumeThread(thread);
                    if (allocation != IntPtr.Zero)
                        Marshal.FreeHGlobal(allocation);
                    CloseHandle(thread);
                }
            }
        }
        return rows.ToArray();
    }
}
'@

if (-not ('NativeThreadSampler' -as [type])) {
    Add-Type -TypeDefinition $source
}

[NativeThreadSampler]::Sample($ProcessId)
