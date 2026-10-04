// Build with Framework64\v4.0.30319\csc.exe /nologo /target:exe /platform:x64
// /out:<output.exe> tools\BackgroundDesktopLauncher.cs
// This manages processes only. It never activates windows, switches desktops,
// sends input, or attaches its thread to the created desktop.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

internal static class BackgroundDesktopLauncher
{
    private const uint GenericRead = 0x80000000, GenericWrite = 0x40000000;
    private const uint CreateNew = 1, OpenExisting = 3, FileAttributeNormal = 0x80;
    private const uint DesktopAccess = 0x000000FF; // Deliberately omits SWITCHDESKTOP.
    private const uint CreateSuspended = 4, CreateNoWindow = 0x08000000;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint StartfUseShowWindow = 1, StartfUseStdHandles = 0x100;
    private const uint Infinite = 0xFFFFFFFF, WaitFailed = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
        public uint dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateDesktopW(string name, IntPtr device,
        IntPtr devmode, uint flags, uint access, ref SECURITY_ATTRIBUTES attributes);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenDesktopW(string name, uint flags, bool inherit, uint access);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformationW(IntPtr handle, int index,
        StringBuilder information, uint length, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string descriptor, uint revision, out IntPtr result, IntPtr size);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        ref SECURITY_ATTRIBUTES attributes, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr attributes,
        int count, uint flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr attributes, uint flags,
        IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnedSize);
    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr attributes);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(string application, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        uint flags, IntPtr environment, string currentDirectory,
        ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInfo);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private static void Check(bool success, string operation)
    {
        if (!success) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }

    private static string Json(string text)
    {
        if (text == null) return "null";
        StringBuilder result = new StringBuilder("\"");
        foreach (char value in text)
        {
            if (value == '"' || value == '\\') result.Append('\\').Append(value);
            else if (value < 32) result.Append("\\u").Append(((int)value).ToString("x4"));
            else result.Append(value);
        }
        return result.Append('"').ToString();
    }

    private static string AbsolutePath(Dictionary<string, string> options, string key)
    {
        string value;
        if (!options.TryGetValue(key, out value) || !Path.IsPathRooted(value))
            throw new ArgumentException(key + " requires an absolute path.");
        return Path.GetFullPath(value);
    }

    private static SafeFileHandle OpenStandardHandle(string path, bool input)
    {
        SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
        attributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        attributes.bInheritHandle = true;
        SafeFileHandle handle = CreateFileW(path, input ? GenericRead : GenericWrite,
            3, ref attributes, input ? OpenExisting : CreateNew, FileAttributeNormal, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "Open redirected handle: " + path);
        }
        return handle;
    }

    private static void WriteManifest(FileStream stream, string json)
    {
        byte[] bytes = new UTF8Encoding(false).GetBytes(json + Environment.NewLine);
        stream.Position = 0;
        stream.Write(bytes, 0, bytes.Length);
        stream.SetLength(bytes.Length);
        stream.Flush(true);
    }

    private static int Main(string[] args)
    {
        IntPtr desktop = IntPtr.Zero, descriptor = IntPtr.Zero;
        IntPtr attributes = IntPtr.Zero, inheritedHandles = IntPtr.Zero;
        bool attributesInitialized = false, running = false;
        PROCESS_INFORMATION child = new PROCESS_INFORMATION();
        SafeFileHandle input = null, output = null, error = null;
        FileStream manifest = null;
        string common = "";
        try
        {
            if (args.Length == 1 && args[0] == "--help")
            {
                Console.WriteLine("--exe ABSOLUTE_EXE --cwd ABSOLUTE_DIR --stdout NEW_LOG --stderr NEW_LOG --manifest NEW_JSON [--args RAW_ARGUMENTS] [--desktop UNIQUE_NAME]");
                Console.WriteLine("Creates an inactive desktop, launches one child with redirected stdio, and waits for its exit. All output paths must be new files. No desktop switching or input APIs are used.");
                return 0;
            }
            Dictionary<string, string> options = new Dictionary<string, string>(StringComparer.Ordinal);
            string[] allowed = { "--exe", "--cwd", "--stdout", "--stderr", "--manifest", "--args", "--desktop" };
            for (int index = 0; index < args.Length; index += 2)
            {
                if (index + 1 >= args.Length || Array.IndexOf(allowed, args[index]) < 0 || options.ContainsKey(args[index]))
                    throw new ArgumentException("Unknown, duplicate, or valueless option: " + args[index]);
                options.Add(args[index], args[index + 1]);
            }
            string executable = AbsolutePath(options, "--exe");
            string directory = AbsolutePath(options, "--cwd");
            string stdout = AbsolutePath(options, "--stdout");
            string stderr = AbsolutePath(options, "--stderr");
            string manifestPath = AbsolutePath(options, "--manifest");
            if (!File.Exists(executable)) throw new FileNotFoundException("Executable missing.", executable);
            if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
            if (String.Equals(stdout, stderr, StringComparison.OrdinalIgnoreCase) ||
                String.Equals(stdout, manifestPath, StringComparison.OrdinalIgnoreCase) ||
                String.Equals(stderr, manifestPath, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("stdout, stderr and manifest paths must be distinct.");
            string rawArguments, name;
            if (!options.TryGetValue("--args", out rawArguments)) rawArguments = "";
            if (!options.TryGetValue("--desktop", out name)) name = "DAH2_Codex_" + Guid.NewGuid().ToString("N");
            if (name.Length == 0 || name.Length > 128 || name.IndexOfAny(new char[] { '\\', '/', '\0' }) >= 0 ||
                String.Equals(name, "Default", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(name, "Winlogon", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Desktop must be a unique, non-default name without path separators.");

            manifest = new FileStream(manifestPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            input = OpenStandardHandle("NUL", true);
            output = OpenStandardHandle(stdout, false);
            error = OpenStandardHandle(stderr, false);

            IntPtr existing = OpenDesktopW(name, 0, false, 1);
            if (existing != IntPtr.Zero)
            {
                CloseDesktop(existing);
                throw new InvalidOperationException("Refusing to reuse an existing desktop: " + name);
            }
            int openError = Marshal.GetLastWin32Error();
            if (openError != 2 && openError != 3)
                throw new Win32Exception(openError, "Check unique desktop name");
            string sid = WindowsIdentity.GetCurrent().User.Value;
            Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                "D:P(A;;GA;;;SY)(A;;GA;;;" + sid + ")", 1, out descriptor, IntPtr.Zero), "Create desktop ACL");
            SECURITY_ATTRIBUTES desktopAttributes = new SECURITY_ATTRIBUTES();
            desktopAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            desktopAttributes.lpSecurityDescriptor = descriptor;
            desktop = CreateDesktopW(name, IntPtr.Zero, IntPtr.Zero, 0, DesktopAccess, ref desktopAttributes);
            Check(desktop != IntPtr.Zero, "Create private inactive desktop");
            StringBuilder stationName = new StringBuilder(256);
            uint needed;
            Check(GetUserObjectInformationW(GetProcessWindowStation(), 2, stationName,
                (uint)(stationName.Capacity * 2), out needed), "Read current window station name");
            string desktopPath = stationName.ToString() + "\\" + name;

            IntPtr attributeSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeSize);
            if (attributeSize == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Size process attributes");
            attributes = Marshal.AllocHGlobal(attributeSize);
            Check(InitializeProcThreadAttributeList(attributes, 1, 0, ref attributeSize), "Initialize process attributes");
            attributesInitialized = true;
            inheritedHandles = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(inheritedHandles, 0, input.DangerousGetHandle());
            Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size, output.DangerousGetHandle());
            Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size * 2, error.DangerousGetHandle());
            Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x00020002), inheritedHandles,
                new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero), "Restrict inherited handles to stdio");

            STARTUPINFOEX startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.StartupInfo.lpDesktop = desktopPath;
            startup.StartupInfo.dwFlags = StartfUseShowWindow | StartfUseStdHandles;
            startup.StartupInfo.wShowWindow = 1; // The child renders only on its inactive desktop.
            startup.StartupInfo.hStdInput = input.DangerousGetHandle();
            startup.StartupInfo.hStdOutput = output.DangerousGetHandle();
            startup.StartupInfo.hStdError = error.DangerousGetHandle();
            startup.lpAttributeList = attributes;
            StringBuilder commandLine = new StringBuilder("\"" + executable + "\" " + rawArguments);
            Check(CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true,
                CreateSuspended | CreateNoWindow | ExtendedStartupInfoPresent, IntPtr.Zero,
                directory, ref startup, out child), "Launch child on inactive desktop");

            common = "\"launcherPid\":" + Process.GetCurrentProcess().Id +
                ",\"childPid\":" + child.dwProcessId + ",\"desktop\":" + Json(desktopPath) +
                ",\"executable\":" + Json(executable) + ",\"workingDirectory\":" + Json(directory) +
                ",\"arguments\":" + Json(rawArguments) + ",\"stdout\":" + Json(stdout) +
                ",\"stderr\":" + Json(stderr) + ",\"startedUtc\":" + Json(DateTime.UtcNow.ToString("o"));
            WriteManifest(manifest, "{" + common + ",\"status\":\"starting\"}");
            Check(ResumeThread(child.hThread) != 0xFFFFFFFF, "Resume child");
            running = true;
            CloseHandle(child.hThread);
            child.hThread = IntPtr.Zero;
            WriteManifest(manifest, "{" + common + ",\"status\":\"running\"}");
            Check(WaitForSingleObject(child.hProcess, Infinite) != WaitFailed, "Wait for child exit");
            uint exitCode;
            Check(GetExitCodeProcess(child.hProcess, out exitCode), "Read child exit code");
            running = false;
            WriteManifest(manifest, "{" + common + ",\"status\":\"exited\",\"exitCode\":" + exitCode +
                ",\"exitedUtc\":" + Json(DateTime.UtcNow.ToString("o")) + "}");
            return unchecked((int)exitCode);
        }
        catch (Exception exception)
        {
            // Do not leave a suspended or unrecorded child after failed startup.
            if (child.hProcess != IntPtr.Zero && !running) TerminateProcess(child.hProcess, 125);
            if (manifest != null)
            {
                try { WriteManifest(manifest, "{" + (common.Length == 0 ? "" : common + ",") +
                    "\"status\":\"launcher_error\",\"error\":" + Json(exception.ToString()) + "}"); }
                catch { }
            }
            Console.Error.WriteLine(exception.ToString());
            return 125;
        }
        finally
        {
            // Preserve the desktop even if reporting fails after a successful launch.
            if (running && child.hProcess != IntPtr.Zero) WaitForSingleObject(child.hProcess, Infinite);
            if (child.hThread != IntPtr.Zero) CloseHandle(child.hThread);
            if (child.hProcess != IntPtr.Zero) CloseHandle(child.hProcess);
            if (attributesInitialized) DeleteProcThreadAttributeList(attributes);
            if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            if (inheritedHandles != IntPtr.Zero) Marshal.FreeHGlobal(inheritedHandles);
            if (input != null) input.Dispose();
            if (output != null) output.Dispose();
            if (error != null) error.Dispose();
            if (manifest != null) manifest.Dispose();
            if (desktop != IntPtr.Zero) CloseDesktop(desktop);
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }
}
