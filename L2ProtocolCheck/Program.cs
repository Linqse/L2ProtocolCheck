using System;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);

    static void Main()
    {
        IntPtr hLib = LoadLibrary("Engine.dll");
        if (hLib == IntPtr.Zero)
        {
            Console.WriteLine("Failed to load Engine.dll");
            return;
        }

        IntPtr procAddr = GetProcAddress(hLib, "?PrepareLoad@FL2ReplayManager@@AAEHXZ");
        if (procAddr == IntPtr.Zero)
        {
            Console.WriteLine("Failed to find the procedure address");
            FreeLibrary(hLib);
            return;
        }

        while (true)
        {
            byte firstByte = Marshal.ReadByte(procAddr);
            if (firstByte != 0xE9)
                break;

            int offset = Marshal.ReadInt32(procAddr + 1);
            procAddr += offset + 5;
        }

        int finalOffset = (Marshal.ReadByte(procAddr + 26) == 104) ? 27 : (Marshal.ReadByte(procAddr + 59) == 104) ? 60 : 0;
        if (finalOffset == 0)
        {
            Console.WriteLine("Offset not found");
            FreeLibrary(hLib);
            return;
        }

        IntPtr versionStringPtr = Marshal.ReadIntPtr(procAddr + finalOffset);
        string versionString = Marshal.PtrToStringAnsi(versionStringPtr);
        Match match = Regex.Match(versionString, @"#(\d+) ");
        if (match.Success)
        {
            string versionNumber = match.Groups[1].Value;
            Console.WriteLine($"Lineage 2 protocol version - {versionNumber}");
            Console.ReadLine();
        }
        else
        {
            Console.WriteLine("Failed to extract protocol version from the string.");
        }

        FreeLibrary(hLib);
    }
}
