using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace ClaudeGuard;

public static class Native
{
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(IntPtr service, int level, byte[] buffer, int size, out int needed);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool StartService(IntPtr service, uint count, IntPtr args);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceObjectSecurity(IntPtr service, uint information, byte[]? descriptor, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetServiceObjectSecurity(IntPtr service, uint information, byte[] descriptor);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);

    public static string Owner(Process process)
    {
        using var query = OpenProcess(0x1000, false, process.Id);
        if (query.IsInvalid || !OpenProcessToken(query.DangerousGetHandle(), 8, out var handle)) throw new Win32Exception();
        using (handle) using (var identity = new WindowsIdentity(handle.DangerousGetHandle())) return identity.User!.Value;
    }
    public static uint ServicePid() => ServiceProcessId(true);
    public static uint ServiceProcessId(bool runningOnly = false)
    {
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) return 0;
        try
        {
            var service = OpenService(manager, Product.ServiceName, 4);
            if (service == IntPtr.Zero) return 0;
            try
            {
                byte[] data = new byte[36];
                if (!QueryServiceStatusEx(service, 0, data, data.Length, out _)) return 0;
                return !runningOnly || BitConverter.ToInt32(data, 4) == 4 ? BitConverter.ToUInt32(data, 28) : 0;
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }
    public static bool ServiceActive()
    {
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) return false;
        try
        {
            var service = OpenService(manager, Product.ServiceName, 4);
            if (service == IntPtr.Zero) return false;
            try
            {
                byte[] data = new byte[36];
                return QueryServiceStatusEx(service, 0, data, data.Length, out _) && BitConverter.ToInt32(data, 4) != 1;
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }
    public static bool TryStartService()
    {
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) return false;
        try
        {
            var service = OpenService(manager, Product.ServiceName, 0x0010);
            if (service == IntPtr.Zero) return false;
            try { return StartService(service, 0, IntPtr.Zero) || Marshal.GetLastWin32Error() == 1056; }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }
    public static void AllowOwnerToStartService(string owner)
    {
        var manager = OpenSCManager(null, null, 1);
        if (manager == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var service = OpenService(manager, Product.ServiceName, 0x00020000 | 0x00040000);
            if (service == IntPtr.Zero) throw new Win32Exception();
            try
            {
                const uint dacl = 4;
                QueryServiceObjectSecurity(service, dacl, null, 0, out uint length);
                if (length is 0 or > 65536) throw new Win32Exception();
                byte[] data = new byte[length];
                if (!QueryServiceObjectSecurity(service, dacl, data, length, out _)) throw new Win32Exception();
                var descriptor = new RawSecurityDescriptor(data, 0);
                if (!AddOwnerStartAccess(descriptor, owner)) return;
                data = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(data, 0);
                if (!SetServiceObjectSecurity(service, dacl, data)) throw new Win32Exception();
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }
    internal static bool AddOwnerStartAccess(RawSecurityDescriptor descriptor, string owner)
    {
        var acl = descriptor.DiscretionaryAcl ?? throw new IOException("Service DACL missing");
        var sid = new SecurityIdentifier(owner);
        const int access = 0x0010 | 0x0004; // SERVICE_START and SERVICE_QUERY_STATUS only.
        bool exists = acl.Cast<GenericAce>().OfType<CommonAce>().Any(ace =>
            ace.AceQualifier == AceQualifier.AccessAllowed && ace.SecurityIdentifier == sid && (ace.AccessMask & access) == access);
        if (exists) return false;
        acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, access, sid, false, null));
        return true;
    }
    public static List<int> LoopbackPorts(int pid)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 3, 0);
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, 2, 3, 0) != 0) return [];
            var count = Marshal.ReadInt32(buffer);
            var ports = new List<int>();
            for (int i = 0; i < count; i++)
            {
                var row = buffer + 4 + 24 * i;
                // Wildcard listeners also accept loopback connections. Requests still go only
                // to 127.0.0.1 and only to listeners owned by the verified kernel process.
                uint address = unchecked((uint)Marshal.ReadInt32(row, 4));
                if (Marshal.ReadInt32(row) != 2 || Marshal.ReadInt32(row, 20) != pid ||
                    (address != 0 && address != 0x0100007f)) continue;
                var raw = Marshal.ReadInt32(row, 8);
                ports.Add(((raw & 255) << 8) | ((raw >> 8) & 255));
            }
            return ports.Distinct().OrderBy(p => p == 9097 ? 0 : 1).Take(16).ToList();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
}
