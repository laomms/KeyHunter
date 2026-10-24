using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// KeyHunterExe64 - 64-bit trace collector.
//   Injects a logging stub over a 5-byte "call" at a caller-supplied RVA,
//   records the two integer arguments (RCX, RDX) of every hit, then reads the
//   trace back. Site discovery is target-specific; this tool only needs the RVA.
//     KeyHunterExe64.exe <target.exe> <outdir> <siteRvaHex> [maxRecords]
class KeyHunterExe64
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool CreateProcessA(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit,
                                      uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr a, UIntPtr size, uint type, uint prot);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool VirtualProtectEx(IntPtr p, IntPtr a, UIntPtr size, uint prot, out uint old);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool WriteProcessMemory(IntPtr p, IntPtr a, byte[] buf, UIntPtr size, out UIntPtr written);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr p, IntPtr a, byte[] buf, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr p, IntPtr a, out MBI64 m, UIntPtr len);
    [StructLayout(LayoutKind.Sequential)]
    struct MBI64 { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect; public uint pad; public ulong RegionSize; public uint State, Protect, Type; public uint pad2; }

    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, ref PBI pbi, int len, out int ret);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO
    {
        public int cb; public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    struct PBI { public IntPtr R1, PebBaseAddress, R2_0, R2_1, UniqueProcessId, R3; }

    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    static bool IsExited(IntPtr h) { uint c; GetExitCodeProcess(h, out c); return c != 259; }

    static long ReadQ(IntPtr h, IntPtr addr, out bool ok)
    {
        byte[] b = new byte[8]; UIntPtr rd;
        ok = ReadProcessMemory(h, addr, b, (UIntPtr)8, out rd);
        return BitConverter.ToInt64(b, 0);
    }

    static void Append(List<byte> c, byte[] v) { c.AddRange(v); }

    static byte[] BuildStub(long buf, long cnt, long callTarget, long backVa)
    {
        var c = new List<byte>();
        c.Add(0x9C);                                   // pushfq
        c.AddRange(new byte[] { 0x50, 0x51, 0x52 });   // push rax, rcx, rdx
        c.AddRange(new byte[] { 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53 }); // push r8..r11
        c.AddRange(new byte[] { 0x48, 0xB8 }); Append(c, BitConverter.GetBytes(buf));   // mov rax, buf
        c.AddRange(new byte[] { 0x49, 0xBA }); Append(c, BitConverter.GetBytes(cnt));   // mov r10, cnt
        c.AddRange(new byte[] { 0x4D, 0x8B, 0x1A });                 // mov r11, [r10]
        c.AddRange(new byte[] { 0x49, 0xC1, 0xE3, 0x04 });           // shl r11, 4
        c.AddRange(new byte[] { 0x48, 0x89, 0x0C, 0x18 });           // mov [rax+r11], rcx
        c.AddRange(new byte[] { 0x48, 0x89, 0x54, 0x18, 0x08 });     // mov [rax+r11+8], rdx
        c.AddRange(new byte[] { 0x4D, 0x8B, 0x1A });                 // mov r11, [r10]
        c.AddRange(new byte[] { 0x49, 0xFF, 0xC3 });                 // inc r11
        c.AddRange(new byte[] { 0x4D, 0x89, 0x1A });                 // mov [r10], r11
        c.AddRange(new byte[] { 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58 }); // pop r11..r8
        c.AddRange(new byte[] { 0x5A, 0x59, 0x58 });                 // pop rdx, rcx, rax
        c.Add(0x9D);                                                 // popfq
        c.Add(0xE8);                                                 // call original
        Append(c, BitConverter.GetBytes((int)(callTarget - (0))));
        c.Add(0xE9);                                                 // jmp back
        Append(c, BitConverter.GetBytes((int)(backVa - (0))));
        return c.ToArray();
    }

    static void Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.WriteLine("usage: KeyHunterExe64.exe <target.exe> <outdir> <siteRvaHex> [maxRecords]");
            return;
        }
        string exe = Path.GetFullPath(args[0]);
        string outDir = Path.GetFullPath(args[1]);
        long siteRva;
        try { siteRva = Convert.ToInt64(args[2].Trim().Replace("0x", "").Replace("0X", ""), 16); }
        catch { Console.WriteLine("bad site RVA"); return; }
        int maxRecords = args.Length > 3 ? int.Parse(args[3]) : 200000;

        if (!File.Exists(exe)) { Console.WriteLine("target not found: " + exe); Environment.ExitCode = 2; return; }
        Directory.CreateDirectory(outDir);
        Console.WriteLine("target    : " + exe);

        var si = new STARTUPINFO(); si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        PROCESS_INFORMATION pi;
        string cmd = "\"" + exe + "\"";
        if (!CreateProcessA(exe, cmd, IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, Path.GetDirectoryName(exe), ref si, out pi))
        {
            Console.WriteLine("CreateProcess failed: " + Marshal.GetLastWin32Error());
            Environment.ExitCode = 3; return;
        }
        Console.WriteLine("started pid=" + pi.dwProcessId);

        try
        {
            PBI pbi = new PBI(); int ret;
            NtQueryInformationProcess(pi.hProcess, 0, ref pbi, Marshal.SizeOf(typeof(PBI)), out ret);
            bool ok;
            long peb = pbi.PebBaseAddress.ToInt64();
            long imageBase = ReadQ(pi.hProcess, (IntPtr)(peb + 0x10), out ok);   // x64: PEB+0x10
            Console.WriteLine("image base = 0x{0:X}", imageBase);

            long site = imageBase + siteRva;
            byte[] five = new byte[5]; UIntPtr got;
            if (!ReadProcessMemory(pi.hProcess, (IntPtr)site, five, (UIntPtr)5, out got))
            {
                Console.WriteLine("cannot read hook site"); Environment.ExitCode = 4; return;
            }
            if (five[0] != 0xE8)
            {
                Console.WriteLine("site is not a call (first byte 0x{0:X2})", five[0]);
                Environment.ExitCode = 4; return;
            }
            long callTarget = site + 5 + BitConverter.ToInt32(five, 1);
            Console.WriteLine("site 0x{0:X} -> call 0x{1:X}", site, callTarget);

            // a 5-byte jmp only reaches +-2GB, so the stub must live near the target
            IntPtr stub = IntPtr.Zero;
            for (long delta = 0x10000; delta < 0x70000000L && stub == IntPtr.Zero; delta += 0x10000)
            {
                foreach (long cand in new long[] { site - delta, site + delta })
                {
                    if (cand <= 0x10000) continue;
                    IntPtr r = VirtualAllocEx(pi.hProcess, (IntPtr)cand, (UIntPtr)512, 0x3000, 0x40);
                    if (r != IntPtr.Zero && Math.Abs(r.ToInt64() - site) < 0x70000000L) { stub = r; break; }
                    if (r != IntPtr.Zero) { /* too far, keep scanning */ }
                }
            }
            if (stub == IntPtr.Zero) { Console.WriteLine("cannot allocate a stub near the target"); Environment.ExitCode = 6; return; }
            IntPtr cnt = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (UIntPtr)64, 0x3000, 0x04);
            IntPtr buf = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (UIntPtr)((long)maxRecords * 16 + 64), 0x3000, 0x04);
            Console.WriteLine("stub=0x{0:X} cnt=0x{1:X} buf=0x{2:X}", stub.ToInt64(), cnt.ToInt64(), buf.ToInt64());

            string stubMode = Environment.GetEnvironmentVariable("KH64_STUB") ?? "full";
            byte[] code;
            if (stubMode == "skip") { code = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90 }; }
            else if (stubMode == "spin") { code = new byte[] { 0xEB, 0xFE, 0x90, 0x90, 0x90 }; }
            else if (stubMode == "bare")
            {
                var b = new List<byte>();
                b.AddRange(new byte[] { 0x48, 0xB8 }); b.AddRange(BitConverter.GetBytes(buf.ToInt64()));
                b.AddRange(new byte[] { 0x49, 0xBA }); b.AddRange(BitConverter.GetBytes(cnt.ToInt64()));
                b.AddRange(new byte[] { 0x4D, 0x8B, 0x1A });             // mov r11,[r10]
                b.AddRange(new byte[] { 0x49, 0xC1, 0xE3, 0x04 });       // shl r11,4
                b.AddRange(new byte[] { 0x48, 0x89, 0x0C, 0x18 });       // mov [rax+r11],rcx
                b.AddRange(new byte[] { 0x48, 0x89, 0x54, 0x18, 0x08 }); // mov [rax+r11+8],rdx
                b.AddRange(new byte[] { 0x49, 0xFF, 0xC3 });             // inc r11
                b.AddRange(new byte[] { 0x4D, 0x89, 0x1A });             // mov [r10],r11
                b.AddRange(new byte[] { 0xE9, 0, 0, 0, 0 });              // jmp back (patched below)
                code = b.ToArray();
            }
            else if (stubMode == "logtrap")
            {
                var lt = new List<byte>(BuildStub(buf.ToInt64(), cnt.ToInt64(), callTarget, site + 5));
                lt.RemoveRange(69, lt.Count - 69);
                lt.Add(0xCC);            // int3 right after the counter increment
                code = lt.ToArray();
            }
            else if (stubMode == "mini")
            {
                var m = new List<byte>();
                m.AddRange(new byte[] { 0x48, 0xB8 }); m.AddRange(BitConverter.GetBytes(buf.ToInt64()));
                m.AddRange(new byte[] { 0x49, 0xBA }); m.AddRange(BitConverter.GetBytes(cnt.ToInt64()));
                m.AddRange(new byte[] { 0x49, 0xFF, 0x02 });     // inc qword ptr [r10]
                m.AddRange(new byte[] { 0xE9, 0, 0, 0, 0 });      // jmp back
                code = m.ToArray();
            }
            else if (stubMode == "nocall")
            {
                var list = new List<byte>(BuildStub(buf.ToInt64(), cnt.ToInt64(), callTarget, site + 5));
                code = list.GetRange(0, 69).ToArray();                 // everything up to the call
                var tail = new List<byte> { 0xE9, 0, 0, 0, 0 };        // jmp back instead of call
                code = new List<byte>(code) { 0 }.GetRange(0, 0).ToArray();
                var full = new List<byte>(list.GetRange(0, 69));
                full.AddRange(new List<byte> { 0xE9, 0, 0, 0, 0 });
                code = full.ToArray();
            }
            else code = BuildStub(buf.ToInt64(), cnt.ToInt64(), callTarget, site + 5);
            // resolution: the stub's call/jmp displacements are relative to their own position
            int callDispAt = (stubMode == "full" || stubMode == "nocall") ? 69 : -1;
            long stubBase = stub.ToInt64();
            if (stubMode == "bare")
            {
                int jmpAt = 42;
                int relJmpBare = (int)((site + 5) - (stubBase + jmpAt + 5));
                BitConverter.GetBytes(relJmpBare).CopyTo(code, jmpAt + 1);
            }
            else if (stubMode == "mini")
            {
                int jmpAt = 23;
                int relJmpMini = (int)((site + 5) - (stubBase + jmpAt + 5));
                BitConverter.GetBytes(relJmpMini).CopyTo(code, jmpAt + 1);
            }
            else if (callDispAt >= 0)
            {
                int relCall = (int)(callTarget - (stubBase + callDispAt + 5));
                BitConverter.GetBytes(relCall).CopyTo(code, callDispAt + 1);
                int jmpAt = callDispAt + 5;
                int relJmp = (int)((site + 5) - (stubBase + jmpAt + 5));
                BitConverter.GetBytes(relJmp).CopyTo(code, jmpAt + 1);
            }

            WriteProcessMemory(pi.hProcess, stub, code, (UIntPtr)code.Length, out got);
            WriteProcessMemory(pi.hProcess, cnt, new byte[8], (UIntPtr)8, out got);
            byte[] jmp = new byte[5];
            if (stubMode == "skip") { for (int i = 0; i < 5; i++) jmp[i] = 0x90; }
            else { jmp[0] = 0xE9; BitConverter.GetBytes((int)(stub.ToInt64() - (site + 5))).CopyTo(jmp, 1); }
            uint old;
            VirtualProtectEx(pi.hProcess, (IntPtr)site, (UIntPtr)16, 0x40, out old);
            WriteProcessMemory(pi.hProcess, (IntPtr)site, jmp, (UIntPtr)5, out got);
            VirtualProtectEx(pi.hProcess, (IntPtr)site, (UIntPtr)16, old, out old);

            byte[] verify = new byte[5];
            ReadProcessMemory(pi.hProcess, (IntPtr)site, verify, (UIntPtr)5, out got);
            Console.WriteLine("site bytes now: " + BitConverter.ToString(verify));
            byte[] sv = new byte[40];
            ReadProcessMemory(pi.hProcess, stub, sv, (UIntPtr)40, out got);
            Console.WriteLine("stub head: " + BitConverter.ToString(sv));
            Console.WriteLine("expect buf=0x{0:X} cnt=0x{1:X}", buf.ToInt64(), cnt.ToInt64());
            byte[] tailDump = new byte[12];
            ReadProcessMemory(pi.hProcess, (IntPtr)(stub.ToInt64() + 67), tailDump, (UIntPtr)12, out got);
            Console.WriteLine("stub tail: " + BitConverter.ToString(tailDump));

            MBI64 mbi;
            VirtualQueryEx(pi.hProcess, stub, out mbi, (UIntPtr)Marshal.SizeOf(typeof(MBI64)));
            Console.WriteLine("stub region: state=0x{0:X} protect=0x{1:X} type=0x{2:X} size=0x{3:X}", mbi.State, mbi.Protect, mbi.Type, mbi.RegionSize);

            bool cok;
            Console.WriteLine("cnt initial = 0x{0:X}  buf[0] = 0x{1:X}", ReadQ(pi.hProcess, cnt, out cok), ReadQ(pi.hProcess, buf, out cok));

            uint prev = ResumeThread(pi.hThread);
            Console.WriteLine("ResumeThread prev=" + prev);
            System.Threading.Thread.Sleep(300);
            Console.WriteLine("alive after 300ms: " + !IsExited(pi.hProcess));

            long last = -1; int stable = 0;
            for (int i = 0; i < 200; i++)
            {
                System.Threading.Thread.Sleep(20);
                long c = ReadQ(pi.hProcess, cnt, out ok);
                if (!ok) break;
                if (c == last) stable++; else { stable = 0; last = c; }
                if (c > 0 && stable >= 3) break;
            }
            Console.WriteLine("records = " + last);
            uint ec; GetExitCodeProcess(pi.hProcess, out ec);
            Console.WriteLine("target exit = 0x" + ec.ToString("X8") + (ec == 259 ? " (still alive)" : ""));
            if (last <= 0) { Console.WriteLine("no records captured"); Environment.ExitCode = 5; return; }

            int count = (int)Math.Min(last, maxRecords);
            byte[] all = new byte[count * 16];
            ReadProcessMemory(pi.hProcess, buf, all, (UIntPtr)all.Length, out got);
            File.WriteAllBytes(Path.Combine(outDir, "ops64.bin"), all);

            var sb = new StringBuilder();
            for (int i = 0; i < Math.Min(count, 5); i++)
                sb.AppendLine("  [" + i + "] a=0x" + BitConverter.ToUInt64(all, i * 16).ToString("X16") +
                              " b=0x" + BitConverter.ToUInt64(all, i * 16 + 8).ToString("X16"));
            Console.WriteLine(sb.ToString().TrimEnd());
            Console.WriteLine("wrote ops64.bin (" + count + " records) to " + outDir);
        }
        finally
        {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}

















