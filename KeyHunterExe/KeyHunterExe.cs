using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Numerics;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// KeyHunterExe - stage 1 for EXE targets (no export table needed).
//   1. CreateProcess(SUSPENDED) with stdout redirected to a file
//   2. locate the image base (PEB), read the original call at the hook site
//   3. allocate stub + trace buffer inside the target, patch the site
//   4. resume, wait for the signing to finish, read the trace back
//   5. recover the modulus from the target image and write ops.bin + meta.json
//
// Generic launch logic:
//   - tries several command-line templates until one makes the target reach
//     the hooked signer (--out/--hold driver style, /p <partner> <outdir>
//     GatherOsState style, or a custom template passed as 6th argument)
//   - traps kernel32/kernelbase!ExitProcess inside the target so the process
//     cannot disappear before the trace is read back (no IAT dependency)
//   - reads the trace buffer incrementally, so nothing is lost even if the
//     target still manages to die
//   - captures the signature from stdout, the --out file, or any file in the
//     output dir (512-hex or base64-encoded 256 bytes)
//   - verifies the modulus with an exact (s^e mod n == EM(hash)) check first
//     and falls back to a generic PKCS#1 v1.5 format check when the signed
//     message is unknown
class KeyHunterExe
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool CreateProcessA(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit,
                                      uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr a, uint size, uint type, uint prot);
    [DllImport("kernel32.dll")] static extern bool VirtualProtectEx(IntPtr p, IntPtr a, uint size, uint prot, out uint old);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr p, IntPtr a, byte[] buf, uint size, out uint written);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr p, IntPtr a, byte[] buf, uint size, out uint read);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr p, IntPtr a, out MBI m, IntPtr l);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateFile(string n, uint acc, uint share, ref SECURITY_ATTRIBUTES sa, uint disp, uint flags, IntPtr tmpl);
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, ref PBI pbi, int len, out int ret);
    [DllImport("kernel32.dll")] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Module32FirstW(IntPtr snap, ref MODULEENTRY32W me);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Module32NextW(IntPtr snap, ref MODULEENTRY32W me);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateRemoteThread(IntPtr h, IntPtr attr, uint stackSize, IntPtr start, IntPtr param, uint flags, out uint tid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeThread(IntPtr h, out uint code);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO
    {
        public int cb; public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    struct PBI { public IntPtr R1, PebBaseAddress, R2_0, R2_1, UniqueProcessId, R3; }
    [StructLayout(LayoutKind.Sequential)]
    struct MBI
    {
        public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect;
        public IntPtr RegionSize; public uint State, Protect, Type;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct MODULEENTRY32W
    {
        public uint dwSize, th32ModuleID, th32ProcessID, GlblcntUsage, ProccntUsage;
        public IntPtr modBaseAddr; public uint modBaseSize; public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    static byte[] BuildStub(int buf, int cnt, int callTarget, int backVa, int stubVa)
    {
        var c = new List<byte>();
        c.Add(0x60);
        c.AddRange(new byte[] { 0xB8 }); c.AddRange(BitConverter.GetBytes(buf));
        c.AddRange(new byte[] { 0x8B, 0x35 }); c.AddRange(BitConverter.GetBytes(cnt));
        c.AddRange(new byte[] { 0x8B, 0x94, 0x24, 0x20, 0, 0, 0 });
        c.AddRange(new byte[] { 0x89, 0x14, 0xF0 });
        c.AddRange(new byte[] { 0x8B, 0x94, 0x24, 0x28, 0, 0, 0 });
        c.AddRange(new byte[] { 0x89, 0x54, 0xF0, 0x04 });
        c.Add(0x46);
        c.AddRange(new byte[] { 0x89, 0x35 }); c.AddRange(BitConverter.GetBytes(cnt));
        c.Add(0x61);
        c.Add(0xE8);
        c.AddRange(BitConverter.GetBytes(callTarget - (stubVa + c.Count + 4)));
        c.Add(0xE9);
        c.AddRange(BitConverter.GetBytes(backVa - (stubVa + c.Count + 4)));
        return c.ToArray();
    }

    static bool g_reported;
    static bool g_trapWarned;

    static int ReadInt(IntPtr h, IntPtr addr)
    {
        byte[] b = new byte[4]; uint r;
        if (!ReadProcessMemory(h, addr, b, 4, out r))
        {
            if (!g_reported) { g_reported = true; Console.WriteLine("ReadProcessMemory(0x" + addr.ToString("X") + ") failed, err=" + Marshal.GetLastWin32Error()); }
            return -1;
        }
        return BitConverter.ToInt32(b, 0);
    }

    static BigInteger FromBE(byte[] be)
    {
        byte[] le = new byte[be.Length + 1];
        for (int i = 0; i < be.Length; i++) le[i] = be[be.Length - 1 - i];
        return new BigInteger(le);
    }

    static BigInteger BI(byte[] le)
    {
        byte[] b = new byte[le.Length + 1];
        Array.Copy(le, b, le.Length);
        return new BigInteger(b);
    }

    static int BitLen(BigInteger v)
    {
        if (v.IsZero) return 0;
        byte[] b = v.ToByteArray();
        int i = b.Length - 1;
        while (i > 0 && b[i] == 0) i--;
        int bits = i * 8; byte top = b[i];
        while (top > 0) { bits++; top >>= 1; }
        return bits;
    }

    static byte[] Em(byte[] hash)
    {
        byte[] di = { 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20 };
        byte[] em = new byte[256];
        em[0] = 0; em[1] = 1;
        int pad = 256 - 3 - 19 - 32;
        for (int i = 0; i < pad; i++) em[2 + i] = 0xFF;
        em[2 + pad] = 0;
        Array.Copy(di, 0, em, 3 + pad, 19);
        Array.Copy(hash, 0, em, 3 + pad + 19, 32);
        return em;
    }

    // Generic PKCS#1 v1.5 shape check: 00 01 FF..FF(>=8) 00 <DER DigestInfo>
    static bool ValidPkcs1(BigInteger r)
    {
        byte[] le = r.ToByteArray();
        if (le.Length > 256) return false;
        byte[] em = new byte[256];
        for (int i = 0; i < le.Length; i++) em[255 - i] = le[i];
        if (em[0] != 0 || em[1] != 1) return false;
        int k = 2;
        while (k < 256 && em[k] == 0xFF) k++;
        if (k - 2 < 8 || k >= 256 || em[k] != 0) return false;
        k++;
        if (256 - k < 15) return false;
        return em[k] == 0x30; // DER SEQUENCE (DigestInfo)
    }

    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("usage: KeyHunterExe.exe <target.exe> <outdir> [siteRva] [e] [holdMs] [argTemplate]");
            Console.WriteLine("  argTemplate (optional): how to make the target perform a signing.");
            Console.WriteLine("    \"direct\"              : suspend the target and remote-call the signer (default first try)");
            Console.WriteLine("    custom template        : placeholders {SIG}=sig file, {OUTDIR}=output dir, {HOLD}=hold ms");
            Console.WriteLine("    default (no template)  : tries \"direct\", \"--out {SIG} --hold {HOLD}\", \"/p WorkBuddy {OUTDIR}\"");
            return;
        }
        string exe = Path.GetFullPath(args[0]);
        string outDir = Path.GetFullPath(args[1]);
        if (!System.IO.File.Exists(exe)) { Console.WriteLine("target not found: " + exe); Environment.ExitCode = 2; return; }
        int siteRva = 0;
        if (args.Length > 2)
        {
            try { siteRva = Convert.ToInt32(args[2].Trim().Replace("0x", "").Replace("0X", ""), 16); }
            catch { siteRva = 0; }
        }
        uint e = args.Length > 3 ? Convert.ToUInt32(args[3]) : 65537u;
        int holdMs = args.Length > 4 ? int.Parse(args[4]) : 8000;
        string tmplArg = args.Length > 5 ? args[5].Trim() : "";
        try { Directory.CreateDirectory(outDir); }
        catch (Exception ex) { Console.WriteLine("cannot create output directory: " + ex.Message); Console.WriteLine("hint: use a writable path, e.g. under your project folder"); Environment.ExitCode = 7; return; }

        var templates = new List<string>();
        if (tmplArg.Length > 0)
        {
            templates.Add(tmplArg);
        }
        else
        {
            templates.Add("direct");                            // remote-call the signer directly
            templates.Add("--out {SIG} --hold {HOLD}");        // driver.cpp style harness
            templates.Add("/p WorkBuddy {OUTDIR}");             // GatherOsState style target
        }

        byte[] ops = null; int opsCount = 0; string sigHex = null; string usedTmpl = null; int hashKnown = 0;
        for (int attempt = 1; attempt <= templates.Count; attempt++)
        {
            string tmpl = templates[attempt - 1];
            Console.WriteLine();
            Console.WriteLine("=== attempt {0}/{1}: launch args: {2} ===", attempt, templates.Count, tmpl);
            byte[] o; int c; string s; int hk;
            int rc = RunAttempt(exe, outDir, attempt, tmpl, siteRva, e, holdMs, out o, out c, out s, out hk);
            if (rc == 0) { ops = o; opsCount = c; sigHex = s; usedTmpl = tmpl; hashKnown = hk; break; }
            if (rc == -1) { Environment.ExitCode = 10; return; }  // hard fail: not the same signer / no hook site
            Console.WriteLine("attempt {0} captured no trace - trying next launch template", attempt);
        }
        if (ops == null)
        {
            Console.WriteLine("all launch attempts failed - the target never reached the hooked signer");
            Console.WriteLine("  -> check the target's expected command line and pass it as the 6th argument");
            Console.WriteLine("     e.g. KeyHunterExe.exe target.exe outdir 0 65537 8000 \"/p Partner {OUTDIR}\"");
            Environment.ExitCode = 10;
            return;
        }

        // write ops.bin, recover the modulus, write meta.json
        try
        {
            File.WriteAllBytes(Path.Combine(outDir, "ops.bin"), ops);

            byte[] hash = new byte[32];
            for (int i = 0; i < 32; i++) hash[i] = (byte)i;
            BigInteger s = FromBE(ParseHex(sigHex));
            BigInteger m = FromBE(Em(hash));

            BigInteger n = RecoverModulusFromImage(exe, s, e, m, hashKnown == 1);
            if (n.IsZero && hashKnown == 1)
            {
                Console.WriteLine("exact-hash modulus check failed - retrying with generic PKCS#1 format check");
                hashKnown = 0;
                n = RecoverModulusFromImage(exe, s, e, m, false);
            }
            if (n.IsZero) { Console.WriteLine("modulus not found"); Environment.ExitCode = 6; return; }
            Console.WriteLine("modulus recovered, {0} bits", BitLen(n));

            var sb = new StringBuilder();
            sb.Append("{\n  \"dll\": \"").Append(exe.Replace("\\", "\\\\")).Append("\",\n");
            sb.Append("  \"hash\": \"").Append(hashKnown == 1 ? ToHex(hash) : "").Append("\",\n");
            sb.Append("  \"hashKnown\": ").Append(hashKnown == 1 ? "true" : "false").Append(",\n");
            sb.Append("  \"signature\": \"").Append(sigHex).Append("\",\n");
            sb.Append("  \"e\": ").Append(e).Append(",\n");
            sb.Append("  \"n\": \"").Append(n.ToString("x")).Append("\",\n");
            sb.Append("  \"ops\": ").Append(opsCount).Append(",\n");
            sb.Append("  \"template\": \"").Append(usedTmpl.Replace("\\", "\\\\").Replace("\"", "\\\"")).Append("\"\n}\n");
            File.WriteAllText(Path.Combine(outDir, "meta.json"), sb.ToString());
            Console.WriteLine("wrote meta.json + ops.bin to " + outDir);
        }
        catch (Exception ex)
        {
            Console.WriteLine("recovery failed: " + ex.Message);
            Environment.ExitCode = 6;
        }
    }

    // Launch template helpers -------------------------------------------------

    static string ExpandTemplate(string tmpl, string sigPath, string outDir, int holdMs)
    {
        return tmpl
            .Replace("{SIG}", "\"" + sigPath + "\"")
            .Replace("{OUTDIR}", "\"" + outDir + "\"")
            .Replace("{HOLD}", holdMs.ToString());
    }

    // Returns 0 on success, -1 on hard fail (wrong target / no hook site),
    // -2 when the attempt produced no usable trace (caller may retry).
    static int RunAttempt(string exe, string outDir, int attempt, string tmpl, int siteRva, uint e, int holdMs,
                          out byte[] opsOut, out int opsCount, out string sigHexOut, out int hashKnown)
    {
        opsOut = null; opsCount = 0; sigHexOut = null; hashKnown = 0;
        g_reported = false; g_trapWarned = false;
        int maxOps = 300000;

        string stdoutPath = Path.Combine(outDir, "target_stdout" + attempt + ".txt");
        string sigPath = Path.Combine(outDir, "sig" + attempt + ".txt");
        foreach (string f in new string[] { stdoutPath, sigPath })
            if (File.Exists(f)) File.Delete(f);

        SECURITY_ATTRIBUTES sa2 = new SECURITY_ATTRIBUTES();
        sa2.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
        sa2.bInheritHandle = true;
        IntPtr hFile = CreateFile(stdoutPath, 0x40000000, 3, ref sa2, 2, 0, IntPtr.Zero);

        var si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        si.dwFlags = 0x100; // STARTF_USESTDHANDLES
        si.hStdOutput = hFile;
        si.hStdError = hFile;
        PROCESS_INFORMATION pi;
        string cmd = "\"" + exe + "\" " + ExpandTemplate(tmpl, sigPath, outDir, holdMs);
        if (!CreateProcessA(exe, cmd, IntPtr.Zero, IntPtr.Zero, true, 0x4 /*CREATE_SUSPENDED*/, IntPtr.Zero, Path.GetDirectoryName(exe), ref si, out pi))
        {
            Console.WriteLine("CreateProcess failed: " + Marshal.GetLastWin32Error());
            CloseHandle(hFile);
            return -1;
        }
        Console.WriteLine("started pid={0}", pi.dwProcessId);
        Console.WriteLine("cmdline: {0}", cmd);

        try
        {
            // image base from PEB
            PBI pbi = new PBI(); int ret;
            NtQueryInformationProcess(pi.hProcess, 0, ref pbi, Marshal.SizeOf(typeof(PBI)), out ret);
            byte[] ib = new byte[4]; uint got;
            ReadProcessMemory(pi.hProcess, (IntPtr)(pbi.PebBaseAddress.ToInt32() + 8), ib, 4, out got);
            int baseAddr = BitConverter.ToInt32(ib, 0);
            Console.WriteLine("image base = 0x{0:X8}", baseAddr);

            int[] funcPat = SigPatterns.Compile(SigPatterns.SignerFunc);
            int[] sitePat = SigPatterns.Compile(SigPatterns.LimbSite);
            int fhits;
            int signer = FindMasked(pi.hProcess, baseAddr, funcPat, 0, out fhits);
            Console.WriteLine("signer fingerprint: {0} hit(s), {1} fixed bytes", fhits, SigPatterns.FixedBytes(funcPat));
            if (signer == 0 || fhits != 1)
            {
                Console.WriteLine(fhits == 0 ? "  -> this target is not the same signer" : "  -> ambiguous: more than one fingerprint hit");
                Console.WriteLine("run KeyDiag.exe on it to see the details");
                return -1;
            }
            Console.WriteLine("signer found at RVA 0x{0:X}", signer - baseAddr);

            int site = siteRva != 0 ? baseAddr + siteRva : 0;
            byte[] siteBytes = new byte[5];
            bool okSite = site != 0 && ReadProcessMemory(pi.hProcess, (IntPtr)site, siteBytes, 5, out got) && siteBytes[0] == 0xE8;
            if (!okSite)
            {
                int shits2;
                site = FindMasked(pi.hProcess, baseAddr, sitePat, SigPatterns.LimbSiteCallOffset, out shits2);
                Console.WriteLine("limb-site fingerprint: {0} hit(s)", shits2);
                if (site == 0) { Console.WriteLine("hook site not found. run KeyDiag.exe on the target, or pass the site RVA explicitly (3rd arg)"); return -1; }
                ReadProcessMemory(pi.hProcess, (IntPtr)site, siteBytes, 5, out got);
                Console.WriteLine("auto-detected hook site RVA 0x{0:X}", site - baseAddr);
            }
            int rel = BitConverter.ToInt32(siteBytes, 1);
            int callTarget = site + 5 + rel;
            Console.WriteLine("hook site 0x{0:X8} -> call 0x{1:X8}", site, callTarget);

            // the target must look like the CRT 64-bit multiply helper: mov eax,[esp+8]; mov ecx,[esp+0Ch]
            byte[] tgt = new byte[8];
            ReadProcessMemory(pi.hProcess, (IntPtr)callTarget, tgt, 8, out got);
            bool looksAllmul = tgt[0] == 0x8B && tgt[1] == 0x44 && tgt[2] == 0x24 && tgt[3] == 0x08
                            && tgt[4] == 0x8B && tgt[5] == 0x4C && tgt[6] == 0x24;
            Console.WriteLine("call target prologue: " + BitConverter.ToString(tgt).Replace("-", " "));
            if (!looksAllmul)
            {
                Console.WriteLine("this call target is not __allmul - the pattern matched unrelated code");
                Console.WriteLine("target is probably not the same signer; pass the correct site RVA or check with KeyDiag");
                return -1;
            }

            // allocate stub + counter + buffer in the target
            IntPtr stub = VirtualAllocEx(pi.hProcess, IntPtr.Zero, 512, 0x3000, 0x40);
            IntPtr cnt = VirtualAllocEx(pi.hProcess, IntPtr.Zero, 64, 0x3000, 0x04);
            IntPtr buf = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)(maxOps * 8 + 64), 0x3000, 0x04);
            Console.WriteLine("stub=0x{0:X8} cnt=0x{1:X8} buf=0x{2:X8}", stub.ToInt32(), cnt.ToInt32(), buf.ToInt32());

            byte[] code = BuildStub(buf.ToInt32(), cnt.ToInt32(), callTarget, site + 5, stub.ToInt32());
            WriteProcessMemory(pi.hProcess, stub, code, (uint)code.Length, out got);
            byte[] zero = new byte[8];
            WriteProcessMemory(pi.hProcess, cnt, zero, 8, out got);

            uint old;
            VirtualProtectEx(pi.hProcess, (IntPtr)site, 16, 0x40, out old);
            byte[] jmp = new byte[5];
            jmp[0] = 0xE9;
            int r2 = stub.ToInt32() - (site + 5);
            jmp[1] = (byte)r2; jmp[2] = (byte)(r2 >> 8); jmp[3] = (byte)(r2 >> 16); jmp[4] = (byte)(r2 >> 24);
            WriteProcessMemory(pi.hProcess, (IntPtr)site, jmp, 5, out got);
            VirtualProtectEx(pi.hProcess, (IntPtr)site, 16, old, out old);

            bool direct = tmpl.Trim().Equals("direct", StringComparison.OrdinalIgnoreCase);
            IntPtr hashBuf = IntPtr.Zero, sigBuf = IntPtr.Zero, sizePtr = IntPtr.Zero, thread = IntPtr.Zero;

            if (!direct)
            {
                IntPtr spin = VirtualAllocEx(pi.hProcess, IntPtr.Zero, 64, 0x3000, 0x40);
                byte[] spinCode = { 0xEB, 0xFE };
                WriteProcessMemory(pi.hProcess, spin, spinCode, 2, out got);

                ResumeThread(pi.hThread);

                // keep-alive #1: patch ExitProcess in the target's own IAT (works only
                // when the exe imports it directly). The loader finishes import
                // binding only after the thread runs, so retry for a while.
                byte[] fileBytes = File.ReadAllBytes(exe);
                int slot = 0;
                for (int i = 0; i < 12; i++)
                {
                    System.Threading.Thread.Sleep(10);
                    slot = PatchExitProcess(pi.hProcess, baseAddr, fileBytes, spin.ToInt32());
                    if (slot != 0) break;
                }
                Console.WriteLine(slot != 0 ? "ExitProcess IAT patched (0x" + slot.ToString("X") + ")" : "ExitProcess not in IAT - relying on the global kernel32/kernelbase trap");

                // keep-alive #2: patch ExitProcess itself inside the target, so ANY
                // module (CRT, msvcrt, ...) trying to exit spins instead of dying.
                // The loader data list fills in right after resume, so retry briefly.
                bool trapped = false;
                for (int i = 0; i < 60 && !trapped; i++)
                {
                    trapped = TrapExitProcessGlobal(pi.hProcess, (uint)pi.dwProcessId);
                    if (!trapped) System.Threading.Thread.Sleep(50);
                }
                if (!trapped) Console.WriteLine("  global trap: could not install within 3s");
            }
            else
            {
                // direct mode: keep the main thread suspended forever (the target's
                // own init/CLI logic never runs) and invoke the signer from a
                // remote thread with the standard fixed hash 00..1F.
                hashBuf = VirtualAllocEx(pi.hProcess, IntPtr.Zero, 64, 0x3000, 0x04);
                sigBuf = VirtualAllocEx(pi.hProcess, IntPtr.Zero, 1024, 0x3000, 0x04);
                sizePtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, 64, 0x3000, 0x04);
                byte[] hash0 = new byte[32];
                for (int i = 0; i < 32; i++) hash0[i] = (byte)i;
                WriteProcessMemory(pi.hProcess, hashBuf, hash0, 32, out got);
                byte[] want = BitConverter.GetBytes(512);
                WriteProcessMemory(pi.hProcess, sizePtr, want, 4, out got);

                // stub: push &dstSize; push dst; push 32; push hash; push 0; call signer; ret 20
                IntPtr callStub = VirtualAllocEx(pi.hProcess, IntPtr.Zero, 64, 0x3000, 0x40);
                var cs = new List<byte>();
                cs.AddRange(new byte[] { 0x68 }); cs.AddRange(BitConverter.GetBytes(sizePtr.ToInt32()));
                cs.AddRange(new byte[] { 0x68 }); cs.AddRange(BitConverter.GetBytes(sigBuf.ToInt32()));
                cs.AddRange(new byte[] { 0x6A, 0x20 });
                cs.AddRange(new byte[] { 0x68 }); cs.AddRange(BitConverter.GetBytes(hashBuf.ToInt32()));
                cs.AddRange(new byte[] { 0x6A, 0x00 });
                cs.AddRange(new byte[] { 0xB8 }); cs.AddRange(BitConverter.GetBytes(signer));
                cs.AddRange(new byte[] { 0xFF, 0xD0 });
                cs.AddRange(new byte[] { 0xC2, 0x04, 0x00 }); // ThreadProc is stdcall(1 param): ret 4
                WriteProcessMemory(pi.hProcess, callStub, cs.ToArray(), (uint)cs.Count, out got);
                Console.WriteLine("direct-call: signer at 0x{0:X}, thread stub at 0x{1:X}", signer, callStub.ToInt32());
                uint tid;
                thread = CreateRemoteThread(pi.hProcess, IntPtr.Zero, 0, callStub, IntPtr.Zero, 0, out tid);
                if (thread == IntPtr.Zero)
                {
                    Console.WriteLine("CreateRemoteThread failed, err=" + Marshal.GetLastWin32Error());
                    return -2;
                }
            }

            // wait until the counter stops growing, reading the trace buffer
            // incrementally so nothing is lost if the target still dies
            byte[] all = new byte[maxOps * 8];
            int last = 0, stable = 0, have = 0;
            bool died = false, threadDone = false;
            uint threadHr = 0;
            int maxLoops = direct ? (holdMs / 25) + 400 : 800;
            for (int i = 0; i < maxLoops; i++)
            {
                System.Threading.Thread.Sleep(25);
                if (direct && thread != IntPtr.Zero && !threadDone)
                {
                    if (WaitForSingleObject(thread, 0) == 0)
                    {
                        threadDone = true;
                        GetExitCodeThread(thread, out threadHr);
                        Console.WriteLine("signer thread finished, exit code 0x{0:X8}", threadHr);
                    }
                }
                int c = ReadInt(pi.hProcess, cnt);
                if (c < 0) { died = true; break; }
                if (c > maxOps) c = maxOps;
                if (c > have)
                {
                    byte[] tmp = new byte[(c - have) * 8];
                    if (ReadProcessMemory(pi.hProcess, (IntPtr)(buf.ToInt32() + have * 8), tmp, (uint)tmp.Length, out got))
                    {
                        Array.Copy(tmp, 0, all, have * 8, tmp.Length);
                        have = c;
                    }
                }
                if (c == last) stable++; else { stable = 0; last = c; }
                if (direct)
                {
                    if (threadDone && stable >= 8) break;
                }
                else
                {
                    if (c > 1000 && stable >= 8) break;
                    // give slow starters (gathering/collecting phase) up to ~12s
                    // before concluding the signer never ran
                    if (c == 0 && i > 480 && stable >= 160) break;
                }
            }
            Console.WriteLine("ops recorded = {0}{1}", have, died ? " (target exited)" : "");
            uint ec; if (GetExitCodeProcess(pi.hProcess, out ec)) Console.WriteLine("target exit code = 0x{0:X8}", ec);
            if (have <= 0)
            {
                Console.WriteLine("no trace was captured with this launch template");
                Console.WriteLine("  -> the hook site is wrong, or the target never performed a signing with these args");
                if (!direct) DumpTargetStdout(stdoutPath);
                return -2;
            }

            // locate the signature
            string sig = null;
            if (direct)
            {
                // signature comes straight from the remote call's output buffer
                byte[] szb = new byte[4];
                ReadProcessMemory(pi.hProcess, sizePtr, szb, 4, out got);
                int sigLen = BitConverter.ToInt32(szb, 0);
                Console.WriteLine("signer returned {0} signature bytes", sigLen);
                if (sigLen < 1 || sigLen > 512)
                {
                    Console.WriteLine("signature size invalid");
                    return -2;
                }
                byte[] raw = new byte[sigLen];
                ReadProcessMemory(pi.hProcess, sigBuf, raw, (uint)sigLen, out got);
                sig = ToHex(raw);
            }
            else
            {
                // wait for and locate the signature (up to ~5s)
                for (int i = 0; i < 50 && sig == null; i++)
                {
                    System.Threading.Thread.Sleep(100);
                    sig = ScanSigSources(sigPath, stdoutPath, outDir);
                }
                if (sig == null)
                {
                    Console.WriteLine("trace captured but signature not found in stdout / sig file / output dir");
                    return -2;
                }
            }
            Console.WriteLine("signature captured");

            opsOut = new byte[have * 8];
            Array.Copy(all, opsOut, opsOut.Length);
            opsCount = have;
            sigHexOut = sig;
            hashKnown = (direct || tmpl.Contains("{SIG}")) ? 1 : 0;
            return 0;
        }
        finally
        {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            CloseHandle(hFile);
        }
    }

    // Signature capture -------------------------------------------------------

    static void DumpTargetStdout(string stdoutPath)
    {
        try
        {
            if (!File.Exists(stdoutPath)) return;
            string[] lines = ReadAllLinesShared(stdoutPath);
            int n = Math.Min(lines.Length, 15);
            if (n == 0) return;
            Console.WriteLine("--- target stdout (first {0} lines) ---", n);
            for (int i = 0; i < n; i++) Console.WriteLine("  | " + lines[i]);
        }
        catch { }
    }

    static string[] ReadAllLinesShared(string path)
    {
        var list = new List<string>();
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var sr = new StreamReader(fs))
        {
            string s;
            while ((s = sr.ReadLine()) != null) list.Add(s);
        }
        return list.ToArray();
    }

    static string ScanSigSources(string sigPath, string stdoutPath, string outDir)
    {
        var files = new List<string>();
        files.Add(sigPath); files.Add(stdoutPath);
        try { foreach (string f in Directory.GetFiles(outDir)) files.Add(f); } catch { }
        foreach (string f in files)
        {
            string s = SigFromFile(f);
            if (s != null) return s;
        }
        return null;
    }

    static string SigFromFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var fi = new FileInfo(path);
            if (fi.Length == 0 || fi.Length > 16 * 1024 * 1024) return null;
            byte[] b = File.ReadAllBytes(path);
            // try ASCII and UTF-16 encodings; hex/base64 are ASCII-safe either way
            string[] texts =
            {
                Encoding.ASCII.GetString(b),
                (b.Length % 2 == 0) ? Encoding.Unicode.GetString(b) : null
            };
            Regex hexRe = new Regex("(?<![0-9a-fA-F])[0-9a-fA-F]{512}(?![0-9a-fA-F])");
            Regex b64Re = new Regex("(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{344})={0,2}(?![A-Za-z0-9+/=])");
            foreach (string text in texts)
            {
                if (text == null) continue;
                Match m = hexRe.Match(text);
                if (m.Success) return m.Value.ToLowerInvariant();
                foreach (Match bm in b64Re.Matches(text))
                {
                    try
                    {
                        byte[] raw = Convert.FromBase64String(bm.Value);
                        if (raw.Length == 256) return ToHex(raw);
                    }
                    catch { }
                }
            }
        }
        catch { }
        return null;
    }

    // Global ExitProcess trap --------------------------------------------------

    static int FindModuleBase(uint pid, string name)
    {
        IntPtr snap = CreateToolhelp32Snapshot(0x18 /*SNAPMODULE|SNAPMODULE32*/, pid);
        if (snap == (IntPtr)(-1) || snap == IntPtr.Zero) return 0;
        try
        {
            var me = new MODULEENTRY32W();
            me.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32W));
            for (bool ok = Module32FirstW(snap, ref me); ok; ok = Module32NextW(snap, ref me))
                if (string.Equals(me.szModule, name, StringComparison.OrdinalIgnoreCase))
                    return (int)me.modBaseAddr;
        }
        catch { }
        finally { CloseHandle(snap); }
        return 0;
    }

    // Resolves an export VA inside a loaded module of the target process.
    // Handles forwarders: returns va=0 and forwarder="KERNELBASE.ExitProcess".
    static int ResolveExport(IntPtr h, int modBase, string func, out string forwarder)
    {
        forwarder = null;
        byte[] b4 = new byte[4]; uint got;
        if (!ReadProcessMemory(h, (IntPtr)(modBase + 0x3C), b4, 4, out got)) return 0;
        int lfa = BitConverter.ToInt32(b4, 0);
        if (!ReadProcessMemory(h, (IntPtr)(modBase + lfa + 24 + 96), b4, 4, out got)) return 0; // DataDirectory[0].VA
        int expRva = BitConverter.ToInt32(b4, 0);
        if (expRva == 0) return 0;
        byte[] exp = new byte[40];
        if (!ReadProcessMemory(h, (IntPtr)(modBase + expRva), exp, 40, out got)) return 0;
        int nFuncs = BitConverter.ToInt32(exp, 20);
        int nNames = BitConverter.ToInt32(exp, 24);
        int aFunc = modBase + BitConverter.ToInt32(exp, 28);
        int aName = modBase + BitConverter.ToInt32(exp, 32);
        int aOrd = modBase + BitConverter.ToInt32(exp, 36);
        byte[] names = new byte[nNames * 4];
        byte[] ords = new byte[nNames * 2];
        byte[] funcs = new byte[Math.Max(nFuncs, 1) * 4];
        if (!ReadProcessMemory(h, (IntPtr)aName, names, (uint)names.Length, out got)) return 0;
        if (!ReadProcessMemory(h, (IntPtr)aOrd, ords, (uint)ords.Length, out got)) return 0;
        if (!ReadProcessMemory(h, (IntPtr)aFunc, funcs, (uint)funcs.Length, out got)) return 0;
        for (int i = 0; i < nNames; i++)
        {
            int nameRva = BitConverter.ToInt32(names, i * 4);
            byte[] nb = new byte[64];
            if (!ReadProcessMemory(h, (IntPtr)(modBase + nameRva), nb, 64, out got)) continue;
            string fn = Encoding.ASCII.GetString(nb).Split('\0')[0];
            if (!string.Equals(fn, func, StringComparison.OrdinalIgnoreCase)) continue;
            int ord = BitConverter.ToUInt16(ords, i * 2);
            if (ord < 0 || ord >= nFuncs) return 0;
            int funcRva = BitConverter.ToInt32(funcs, ord * 4);
            int va = modBase + funcRva;
            // forwarder detection: export points at an ASCII "MODULE.Function" string
            byte[] fb = new byte[48];
            if (ReadProcessMemory(h, (IntPtr)va, fb, 48, out got))
            {
                int z = Array.IndexOf(fb, (byte)0);
                if (z > 0 && z < 40)
                {
                    string s = Encoding.ASCII.GetString(fb, 0, z);
                    int dot = s.IndexOf('.');
                    if (dot > 0 && dot == s.LastIndexOf('.') && IsForwarderLike(s))
                    { forwarder = s; return 0; }
                }
            }
            return va;
        }
        return 0;
    }

    static bool IsForwarderLike(string s)
    {
        foreach (char c in s)
            if (!(char.IsLetterOrDigit(c) || c == '.' || c == '_')) return false;
        return true;
    }

    // Patches the first bytes of ExitProcess inside the target with EB FE
    // (spin forever). Works regardless of which module imports ExitProcess,
    // because everyone ends up calling the same kernel32/kernelbase code.
    static bool TrapExitProcessGlobal(IntPtr h, uint pid)
    {
        try
        {
            foreach (string mod in new string[] { "kernel32.dll", "kernelbase.dll" })
            {
                int mb = FindModuleBase(pid, mod);
                if (mb == 0)
                {
                    if (!g_trapWarned) Console.WriteLine("  global trap: " + mod + " module not found yet");
                    continue;
                }
                string fwd;
                int va = ResolveExport(h, mb, "ExitProcess", out fwd);
                if (va == 0)
                {
                    if (fwd != null) Console.WriteLine("  " + mod + "!ExitProcess forwards to " + fwd);
                    continue;
                }
                byte[] cur = new byte[2]; uint got;
                ReadProcessMemory(h, (IntPtr)va, cur, 2, out got);
                if (cur[0] == 0xEB && cur[1] == 0xFE)
                {
                    Console.WriteLine("  global trap: ExitProcess already trapped (0x{0:X})", va);
                    return true;
                }
                uint old;
                VirtualProtectEx(h, (IntPtr)va, 2, 0x40, out old);
                bool okw = WriteProcessMemory(h, (IntPtr)va, new byte[] { 0xEB, 0xFE }, 2, out got);
                VirtualProtectEx(h, (IntPtr)va, 2, old, out old);
                Console.WriteLine(okw
                    ? "  global trap: " + mod + "!ExitProcess (0x" + va.ToString("X") + ") now spins - target cannot exit"
                    : "  global trap: write to " + mod + "!ExitProcess failed");
                if (okw) return true;
            }
            Console.WriteLine("  global trap: no patchable ExitProcess found");
            g_trapWarned = true;
        }
        catch (Exception ex) { Console.WriteLine("  global trap failed: " + ex.Message); }
        return false;
    }

    // Modulus recovery ----------------------------------------------------------

    // Scans the on-disk image for 2048-bit odd candidates and validates them.
    // exact=true  : cand must satisfy s^e mod cand == m (signed message known)
    // exact=false : PKCS#1 v1.5 format check on s^e mod cand (message unknown)
    static BigInteger RecoverModulusFromImage(string exe, BigInteger s, uint e, BigInteger m, bool exact)
    {
        byte[] img = File.ReadAllBytes(exe);
        int lfanew = BitConverter.ToInt32(img, 0x3C);
        int nsec = BitConverter.ToUInt16(img, lfanew + 6);
        int optSize = BitConverter.ToUInt16(img, lfanew + 20);
        int secOff = lfanew + 24 + optSize;
        for (int i = 0; i < nsec; i++)
        {
            int vs = BitConverter.ToInt32(img, secOff + i * 40 + 8);
            int rs = BitConverter.ToInt32(img, secOff + i * 40 + 16);
            int rp = BitConverter.ToInt32(img, secOff + i * 40 + 20);
            int len = Math.Min(Math.Max(vs, rs), img.Length - rp);
            if (len <= 256) continue;
            byte[] data = new byte[len];
            Array.Copy(img, rp, data, 0, len);
            for (int off = 0; off + 256 <= data.Length; off += 4)
            {
                if ((data[off] & 1) == 0) continue;
                BigInteger cand = BI(Slice(data, off, 256));
                if (BitLen(cand) != 2048 || cand <= s) continue;
                BigInteger r = BigInteger.ModPow(s, e, cand);
                if (exact ? r == m : ValidPkcs1(r)) return cand;
            }
        }
        return BigInteger.Zero;
    }

    // Generic scanning helpers ---------------------------------------------------

    static int FindPattern(IntPtr h, int baseAddr, byte[] pat, int addAfter)
    {
        long addr = baseAddr, end = baseAddr + 0x400000;
        while (addr < end)
        {
            MBI mbi;
            if (VirtualQueryEx(h, (IntPtr)(int)addr, out mbi, (IntPtr)Marshal.SizeOf(typeof(MBI))) == IntPtr.Zero) break;
            long b = (long)mbi.BaseAddress, sz = (long)mbi.RegionSize;
            if (b > end) break;
            if ((int)mbi.AllocationBase == baseAddr && mbi.State == 0x1000 && (mbi.Protect & 0x66) != 0 && (mbi.Protect & 0x100) == 0 && sz < 0x400000)
            {
                byte[] buf = new byte[sz]; uint got;
                if (ReadProcessMemory(h, (IntPtr)b, buf, (uint)sz, out got))
                {
                    for (int i = 0; i + pat.Length <= buf.Length; i++)
                    {
                        bool ok = true;
                        for (int j = 0; j < pat.Length; j++) if (buf[i + j] != pat[j]) { ok = false; break; }
                        if (ok) return (int)(b + i + addAfter);
                    }
                }
            }
            addr = b + sz;
            if (sz <= 0) addr += 0x1000;
        }
        return 0;
    }

    // Patches the ExitProcess IAT entry to spin forever, so the target cannot
    // disappear before we read the trace back. Returns the patched slot or 0.
    static int PatchExitProcess(IntPtr h, int baseAddr, byte[] fileBytes, int stubAddr)
    {
        try
        {
            int lfanew = BitConverter.ToInt32(fileBytes, 0x3C);
            int nsec = BitConverter.ToUInt16(fileBytes, lfanew + 6);
            int optSize = BitConverter.ToUInt16(fileBytes, lfanew + 20);
            int secOff = lfanew + 24 + optSize;
            var secs = new List<int[]>();
            for (int i = 0; i < nsec; i++)
            {
                int va = BitConverter.ToInt32(fileBytes, secOff + i * 40 + 12);
                int vs = BitConverter.ToInt32(fileBytes, secOff + i * 40 + 8);
                int rp = BitConverter.ToInt32(fileBytes, secOff + i * 40 + 20);
                int rs = BitConverter.ToInt32(fileBytes, secOff + i * 40 + 16);
                secs.Add(new int[] { va, vs, rp, rs });
            }
            Func<int, int> r2o = delegate (int rva)
            {
                foreach (int[] s in secs)
                    if (rva >= s[0] && rva < s[0] + Math.Max(s[1], s[3])) return s[2] + (rva - s[0]);
                return -1;
            };
            int impRva = BitConverter.ToInt32(fileBytes, lfanew + 24 + 104);
            int pos = r2o(impRva);
            if (pos <= 0) return 0;
            for (int d = 0; d < 64; d++)
            {
                int desc = pos + d * 20;
                int oft = BitConverter.ToInt32(fileBytes, desc);
                int nameRva = BitConverter.ToInt32(fileBytes, desc + 12);
                int ft = BitConverter.ToInt32(fileBytes, desc + 16);
                if (oft == 0 && nameRva == 0 && ft == 0) break;
                int nameOff = r2o(nameRva);
                if (nameOff < 0) continue;
                int e = nameOff; while (e < fileBytes.Length && fileBytes[e] != 0) e++;
                string mod = Encoding.ASCII.GetString(fileBytes, nameOff, e - nameOff);
                if (!mod.ToLower().Contains("kernel32")) continue;
                int thunk = oft != 0 ? oft : ft;
                int toff = r2o(thunk);
                if (toff < 0) continue;
                for (int i = 0; ; i++)
                {
                    int ent = BitConverter.ToInt32(fileBytes, toff + i * 4);
                    if (ent == 0) break;
                    if ((ent & 0x80000000) != 0) continue;
                    int nOff = r2o(ent);
                    if (nOff < 0) continue;
                    int ne = nOff + 2; while (ne < fileBytes.Length && fileBytes[ne] != 0) ne++;
                    string fn = Encoding.ASCII.GetString(fileBytes, nOff + 2, ne - nOff - 2);
                    if (fn == "ExitProcess")
                    {
                        int slot = baseAddr + ft + i * 4;
                        byte[] v = BitConverter.GetBytes(stubAddr);
                        uint w;
                        VirtualProtectEx(h, (IntPtr)slot, 4, 0x04, out w);
                        bool okw = WriteProcessMemory(h, (IntPtr)slot, v, 4, out w);
                        VirtualProtectEx(h, (IntPtr)slot, 4, w, out w);
                        byte[] chk = new byte[4]; uint rd;
                        ReadProcessMemory(h, (IntPtr)slot, chk, 4, out rd);
                        Console.WriteLine("  IAT write ok=" + okw + " slot now=0x" + BitConverter.ToInt32(chk, 0).ToString("X") + " (want 0x" + stubAddr.ToString("X") + ")");
                        return slot;
                    }
                }
            }
        }
        catch { }
        return 0;
    }

    static int FindMasked(IntPtr h, int baseAddr, int[] pat, int addAfter, out int hits)
    {
        hits = 0; int found = 0;
        long addr = baseAddr, end = baseAddr + 0x400000;
        while (addr < end)
        {
            MBI mbi;
            if (VirtualQueryEx(h, (IntPtr)(int)addr, out mbi, (IntPtr)Marshal.SizeOf(typeof(MBI))) == IntPtr.Zero) break;
            long b = (long)mbi.BaseAddress, sz = (long)mbi.RegionSize;
            if (b > end) break;
            if ((int)mbi.AllocationBase == baseAddr && mbi.State == 0x1000 && (mbi.Protect & 0x66) != 0 && (mbi.Protect & 0x100) == 0 && sz < 0x400000)
            {
                byte[] buf = new byte[sz]; uint got;
                if (ReadProcessMemory(h, (IntPtr)b, buf, (uint)sz, out got))
                {
                    var list = SigPatterns.FindAll(buf, 0, buf.Length, pat);
                    foreach (int off in list) { hits++; if (found == 0) found = (int)(b + off); }
                    if (found != 0 && hits > 4) break;
                }
            }
            addr = b + sz;
            if (sz <= 0) addr += 0x1000;
        }
        return found == 0 ? 0 : found + addAfter;
    }

    static byte[] ParseHex(string s)
    {
        byte[] b = new byte[s.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return b;
    }

    static byte[] Slice(byte[] b, int off, int len)
    {
        byte[] r = new byte[len];
        Array.Copy(b, off, r, 0, len);
        return r;
    }

    static string ToHex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (byte x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }
}
