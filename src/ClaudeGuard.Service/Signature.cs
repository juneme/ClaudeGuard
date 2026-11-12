using System.Runtime.InteropServices;

namespace ClaudeGuard;

internal static class Signature
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FileInfo { public uint Size; public string Path; public IntPtr Handle; public IntPtr Subject; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint Size; public IntPtr Policy; public IntPtr Sip; public uint Ui; public uint Revocation;
        public uint Choice; public IntPtr File; public uint StateAction; public IntPtr State; public IntPtr Url;
        public uint Flags; public uint Context;
    }
    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr window, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref TrustData data);
    public static bool Verify(string path)
    {
        var file = new FileInfo { Size = (uint)Marshal.SizeOf<FileInfo>(), Path = path };
        var ptr = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
        try
        {
            Marshal.StructureToPtr(file, ptr, false);
            var data = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), Ui = 2, Choice = 1, File = ptr, Flags = 0x1000 };
            return WinVerifyTrust(new IntPtr(-1), new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE"), ref data) == 0;
        }
        finally { Marshal.DestroyStructure<FileInfo>(ptr); Marshal.FreeHGlobal(ptr); }
    }
}
