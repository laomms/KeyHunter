using System;
using System.IO;
using System.Text;
using System.Numerics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

// KeyHunter - 32-bit DLL collector (runs in-process, LoadLibrary the target)
//  * loads the target DLL and calls its signing export with a known message
//  * recovers the RSA modulus by scanning module memory for N with s^e == m (mod N)
//  * detours the limb-multiply site and records every (A_limb, B_limb) pair
//  * writes ops.bin + meta.json for the analyzer
//
// Everything is auto-detected, so a relinked / re-optimised build of the signer
// works without changing any hardcoded RVA:
//   - the limb-multiply site comes from the SigPatterns.LimbSite fingerprint
//   - the __allmul target is read out of the call instruction itself
//   - the export is picked by probing the export table (name preference + verify)
//   - the calling convention is inferred from the RET encoding of the export
class KeyHunter
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr LoadLibrary(string p);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr m, string n);
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr a, uint size, uint type, uint prot);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr a, uint size, uint prot, out uint old);
    [DllImport("kernel32.dll")]
    static extern void CopyMemory(IntPtr dst, byte[] src, uint len);
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualQuery(IntPtr a, out MBI m, IntPtr l);

    [StructLayout(LayoutKind.Sequential)]
    struct MBI
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State, Protect, Type;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SignFnStd(IntPtr h, byte[] hash, int len, byte[] dst, ref uint size);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int SignFnCdecl(IntPtr h, byte[] hash, int len, byte[] dst, ref uint size);

    struct Sec { public string Name; public int VA, VSize, RawPtr, RawSize; }
    struct Exp { public string Name; public int Rva; }

    static IntPtr g_buf, g_cnt;

    // ---------- portable helpers ----------

    static byte[] BuildStub(int buf, int cnt, int callTarget, int backVa, int stubVa, int maxOps)
    {
        var c = new List<byte>();
        c.Add(0x60);                                                        // pushad
        c.Add(0xB8); c.AddRange(BitConverter.GetBytes(buf));                // mov eax, buf
        c.Add(0x8B); c.Add(0x35); c.AddRange(BitConverter.GetBytes(cnt));   // mov esi, [cnt]
        c.Add(0x81); c.Add(0xFE); c.AddRange(BitConverter.GetBytes(maxOps));// cmp esi, maxOps
        int jgeIdx = c.Count;
        c.Add(0x7D); c.Add(0x00);                                           // jge  short skip
        c.AddRange(new byte[] { 0x8B, 0x94, 0x24, 0x20, 0, 0, 0 });         // mov edx,[esp+20h]
        c.AddRange(new byte[] { 0x89, 0x14, 0xF0 });                        // mov [eax+esi*8],edx
        c.AddRange(new byte[] { 0x8B, 0x94, 0x24, 0x28, 0, 0, 0 });         // mov edx,[esp+28h]
        c.AddRange(new byte[] { 0x89, 0x54, 0xF0, 0x04 });                  // mov [eax+esi*8+4],edx
        c.Add(0x46);                                                        // inc esi
        c.Add(0x89); c.Add(0x35); c.AddRange(BitConverter.GetBytes(cnt));   // mov [cnt],esi
        c[jgeIdx + 1] = (byte)(c.Count - (jgeIdx + 2));                     // skip:
        c.Add(0x61);                                                        // popad
        c.Add(0xE8); c.AddRange(BitConverter.GetBytes(callTarget - (stubVa + c.Count + 4)));
        c.Add(0xE9); c.AddRange(BitConverter.GetBytes(backVa - (stubVa + c.Count + 4)));
        return c.ToArray();
    }

    static BigInteger BI(byte[] le)
    {
        byte[] b = new byte[le.Length + 1];
        Array.Copy(le, b, le.Length);      // trailing 0 keeps it positive
        return new BigInteger(b);
    }

    static BigInteger FromBE(byte[] be)
    {
        byte[] le = new byte[be.Length + 1];
        for (int i = 0; i < be.Length; i++) le[i] = be[be.Length - 1 - i];
        return new BigInteger(le);
    }

    static byte[] Em(byte[] hash, int emLen)
    {
        byte[] di = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
        byte[] em = new byte[emLen];
        em[0] = 0x00; em[1] = 0x01;
        int pad = emLen - 3 - 19 - 32;
        if (pad < 8) return null;                       // key too small for SHA-256 PKCS#1 v1.5
        for (int i = 0; i < pad; i++) em[2 + i] = 0xFF;
        em[2 + pad] = 0x00;
        Array.Copy(di, 0, em, 3 + pad, 19);
        Array.Copy(hash, 0, em, 3 + pad + 19, 32);
        return em;
    }

    static List<KeyValuePair<int, byte[]>> ModuleRegions(int baseAddr, long imageSize)
    {
        var res = new List<KeyValuePair<int, byte[]>>();
        long addr = baseAddr;
        long end = baseAddr + imageSize;
        while (addr < end)
        {
            MBI m;
            if (VirtualQuery((IntPtr)(int)addr, out m, (IntPtr)Marshal.SizeOf(typeof(MBI))) == IntPtr.Zero) break;
            long b = (long)m.BaseAddress, sz = (long)m.RegionSize;
            if (b > end) break;
            if ((int)m.AllocationBase == baseAddr && m.State == 0x1000 && (m.Protect & 0x66) != 0 && (m.Protect & 0x100) == 0)
            {
                byte[] buf = new byte[sz];
                try { Marshal.Copy((IntPtr)b, buf, 0, (int)sz); res.Add(new KeyValuePair<int, byte[]>((int)(b - baseAddr), buf)); }
                catch { }
            }
            addr = b + sz;
            if (sz <= 0) addr += 0x1000;
        }
        return res;
    }

    // ---------- PE parsing (file image) ----------

    static bool ParsePE(string path, out byte[] d, out List<Sec> secs, out int machine)
    {
        d = null; secs = new List<Sec>(); machine = 0;
        try { d = File.ReadAllBytes(path); } catch (Exception e) { Console.WriteLine("cannot read " + path + ": " + e.Message); return false; }
        if (d.Length < 0x200 || BitConverter.ToUInt16(d, 0) != 0x5A4D) { Console.WriteLine("not a PE image"); return false; }
        int lfa = BitConverter.ToInt32(d, 0x3C);
        if (lfa <= 0 || lfa + 24 > d.Length || BitConverter.ToUInt32(d, lfa) != 0x4550) { Console.WriteLine("bad PE header"); return false; }
        machine = BitConverter.ToUInt16(d, lfa + 4);
        int nsec = BitConverter.ToUInt16(d, lfa + 6);
        int optsz = BitConverter.ToUInt16(d, lfa + 20);
        int sect = lfa + 24 + optsz;
        for (int i = 0; i < nsec; i++)
        {
            int o = sect + i * 40;
            if (o + 40 > d.Length) break;
            Sec s;
            s.Name = Encoding.ASCII.GetString(d, o, 8).TrimEnd('\0');
            s.VSize = BitConverter.ToInt32(d, o + 8);
            s.VA = BitConverter.ToInt32(d, o + 12);
            s.RawSize = BitConverter.ToInt32(d, o + 16);
            s.RawPtr = BitConverter.ToInt32(d, o + 20);
            secs.Add(s);
        }
        return true;
    }

    static int Rva2Off(List<Sec> secs, int rva)
    {
        foreach (Sec s in secs)
        {
            int vs = s.VSize > 0 ? s.VSize : s.RawSize;
            if (rva >= s.VA && rva < s.VA + vs)
            {
                int off = s.RawPtr + (rva - s.VA);
                if (off >= 0 && off < 0x7FFFFFFF) return off;
            }
        }
        return -1;
    }

    static int DataDir(byte[] d, int lfa, int idx)
    {
        int opt = lfa + 24;
        int magic = BitConverter.ToUInt16(d, opt);
        int dd = magic == 0x10B ? opt + 96 : opt + 112;
        return dd + idx * 8;
    }

    static List<Exp> ReadExports(byte[] d, List<Sec> secs)
    {
        var res = new List<Exp>();
        int lfa = BitConverter.ToInt32(d, 0x3C);
        int dd = DataDir(d, lfa, 0);
        int erva = BitConverter.ToInt32(d, dd);
        if (erva == 0) return res;
        int eo = Rva2Off(secs, erva);
        if (eo < 0 || eo + 40 > d.Length) return res;
        int nfun = BitConverter.ToInt32(d, eo + 20);
        int nname = BitConverter.ToInt32(d, eo + 24);
        int afun = BitConverter.ToInt32(d, eo + 28);
        int anam = BitConverter.ToInt32(d, eo + 32);
        int aord = BitConverter.ToInt32(d, eo + 36);
        int ofun = Rva2Off(secs, afun), onam = Rva2Off(secs, anam), oord = Rva2Off(secs, aord);
        if (ofun < 0 || onam < 0 || oord < 0) return res;
        for (int i = 0; i < nname && i < 4096; i++)
        {
            int nr = BitConverter.ToInt32(d, onam + i * 4);
            int no = Rva2Off(secs, nr);
            if (no < 0) continue;
            int end = Array.IndexOf(d, (byte)0, no);
            if (end < 0) continue;
            string nm = Encoding.ASCII.GetString(d, no, end - no);
            int idx = BitConverter.ToUInt16(d, oord + i * 2);
            if (idx >= nfun) continue;
            int fr = BitConverter.ToInt32(d, ofun + idx * 4);
            if (fr == 0) continue;                       // forwarded / unused ordinal
            res.Add(new Exp { Name = nm, Rva = fr });
        }
        return res;
    }

    static List<int> FindPattern(byte[] d, int[] pat, int start, int len)
    {
        var hits = new List<int>();
        int end = start + len - pat.Length;
        for (int i = start; i <= end; i++)
        {
            bool ok = true;
            for (int j = 0; j < pat.Length; j++)
                if (pat[j] >= 0 && d[i + j] != pat[j]) { ok = false; break; }
            if (ok) hits.Add(i);
        }
        return hits;
    }

    static bool SiteMatches(byte[] d, int off, int[] pat)
    {
        if (off < 0 || off + pat.Length > d.Length) return false;
        for (int j = 0; j < pat.Length; j++)
            if (pat[j] >= 0 && d[off + j] != pat[j]) return false;
        return true;
    }

    // ---------- signer probing ----------

    static int CallSign(IntPtr fp, CallingConvention cc, byte[] hash, byte[] dst, ref uint sz)
    {
        if (cc == CallingConvention.Cdecl)
        {
            var f = (SignFnCdecl)Marshal.GetDelegateForFunctionPointer(fp, typeof(SignFnCdecl));
            return f(IntPtr.Zero, hash, 32, dst, ref sz);
        }
        var g = (SignFnStd)Marshal.GetDelegateForFunctionPointer(fp, typeof(SignFnStd));
        return g(IntPtr.Zero, hash, 32, dst, ref sz);
    }

    // Try both x86 conventions. stdcall is the MASM default, so it goes first;
    // a wrong guess is caught by calling twice and demanding identical results
    // (a mismatched RET imm16 leaves ESP shifted and the second call disagrees).
    static bool ProbeSign(IntPtr fp, byte[] hash, byte[] dst, out CallingConvention cc, out uint sz, out int hr)
    {
        foreach (CallingConvention c in new CallingConvention[] { CallingConvention.StdCall, CallingConvention.Cdecl })
        {
            try
            {
                uint s1 = 1024;
                int h1 = CallSign(fp, c, hash, dst, ref s1);
                if (h1 != 0 || s1 < 64 || s1 > 1024) continue;
                byte[] first = Slice(dst, 0, (int)s1);
                uint s2 = 1024;
                byte[] d2 = new byte[1024];
                int h2 = CallSign(fp, c, hash, d2, ref s2);
                if (h2 != 0 || s2 != s1) continue;
                bool same = true;
                for (int i = 0; i < first.Length; i++) if (first[i] != d2[i]) { same = false; break; }
                if (!same) continue;
                cc = c; sz = s1; hr = h1;
                return true;
            }
            catch { }
        }
        cc = CallingConvention.StdCall; sz = 0; hr = -1;
        return false;
    }

    static int Score(string n)
    {
        string s = n.ToLowerInvariant();
        if (s.Contains("signpkcs")) return 5;
        if (s.Contains("sign")) return 4;
        if (s.Contains("pkcs")) return 3;
        if (s.Contains("rsa")) return 2;
        if (s.Contains("modexp") || s.Contains("priv")) return 1;
        return 0;
    }

    static int Main(string[] args)
    {
        try { return Run(args); }
        catch (SEHException se)
        {
            Console.WriteLine("[-] hardware exception while calling into the target (0x" + se.ErrorCode.ToString("X8") + ")");
            Console.WriteLine("  -> the hook site or the export signature does not match this build");
            return 5;
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] " + ex.GetType().Name + ": " + ex.Message);
            return 6;
        }
    }

    static int Run(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("usage: KeyHunter.exe <dll> <outdir> [hookRva] [allmulRva] [exportName]");
            Console.WriteLine("  pass 0 / auto for hookRva or exportName to auto-detect");
            return 1;
        }
        string dll = args[0];
        string outDir = args[1];
        int hookRva = args.Length > 2 ? ParseHex(args[2]) : 0;
        int allmulRva = args.Length > 3 ? ParseHex(args[3]) : 0;
        string exportName = args.Length > 4 ? args[4] : "";
        if (exportName.Equals("0", StringComparison.OrdinalIgnoreCase)) exportName = "";
        Directory.CreateDirectory(outDir);

        byte[] file; List<Sec> secs; int machine;
        if (!ParsePE(dll, out file, out secs, out machine)) return 2;
        if (machine != 0x14C)
        {
            Console.WriteLine("not a 32-bit image (machine=0x" + machine.ToString("X") + ") - use the x64 collector");
            return 2;
        }

        IntPtr mod = LoadLibrary(dll);
        if (mod == IntPtr.Zero)
        {
            int le = Marshal.GetLastWin32Error();
            Console.WriteLine("LoadLibrary failed: " + le);
            if (le == 193) Console.WriteLine("  -> 193 = ERROR_BAD_EXE_FORMAT: not a 32-bit DLL (x64 build?)");
            return 2;
        }
        int baseAddr = mod.ToInt32();
        Console.WriteLine("module base = 0x{0:X8}", baseAddr);

        // ---- locate the signing export (probe, do not trust a hardcoded name) ----
        var exports = ReadExports(file, secs);
        string[] preferred = string.IsNullOrEmpty(exportName) || exportName.Equals("auto", StringComparison.OrdinalIgnoreCase)
            ? new string[] { "VRSAVaultSignPKCS" }
            : new string[] { exportName };
        var order = new List<Exp>();
        foreach (string want in preferred)
            foreach (Exp e in exports)
                if (e.Name.Equals(want, StringComparison.OrdinalIgnoreCase)) order.Add(e);
        var rest = new List<Exp>(exports);
        rest.RemoveAll(e => order.Exists(o => o.Name == e.Name && o.Rva == e.Rva));
        rest.Sort(delegate (Exp a, Exp b) { return Score(b.Name).CompareTo(Score(a.Name)); });
        order.AddRange(rest);
        if (order.Count == 0) { Console.WriteLine("the DLL exports nothing by name"); return 3; }
        Console.WriteLine("exports: " + string.Join(", ", exports.ConvertAll(e => e.Name).ToArray()));

        byte[] hash = new byte[32];
        for (int i = 0; i < 32; i++) hash[i] = (byte)i;

        byte[] dst = new byte[1024];
        IntPtr signFp = IntPtr.Zero;
        string signName = null;
        CallingConvention cc = CallingConvention.StdCall;
        uint sz = 1024;
        int hr = -1;
        foreach (Exp e in order)
        {
            IntPtr fp = GetProcAddress(mod, e.Name);
            if (fp == IntPtr.Zero) continue;
            CallingConvention tcc; uint ts; int th;
            if (!ProbeSign(fp, hash, dst, out tcc, out ts, out th)) { Console.WriteLine("  probe " + e.Name + ": not a signer"); continue; }
            signFp = fp; signName = e.Name; sz = ts; hr = th; cc = tcc;
            break;
        }
        if (signFp == IntPtr.Zero) { Console.WriteLine("no export behaved like a signer - pass the name as arg 5"); return 3; }
        int keyBytes = (int)sz;
        Console.WriteLine("signing export = {0} ({1}-bit key, {2})", signName, keyBytes * 8, cc == CallingConvention.StdCall ? "stdcall" : "cdecl");

        BigInteger s = FromBE(Slice(dst, 0, keyBytes));
        BigInteger m = FromBE(Em(hash, keyBytes));
        Console.WriteLine("baseline signature captured");

        // ---- public exponent ----
        uint e_ = 65537;
        IntPtr pubp = GetProcAddress(mod, "VbnRsaVault_GetPubParams");
        if (pubp != IntPtr.Zero)
        {
            var pub = (PubFnStd)Marshal.GetDelegateForFunctionPointer(pubp, typeof(PubFnStd));
            uint[] pb = new uint[2]; uint ps = 8;
            try { pub(pb, ref ps); if (pb[0] > 1 && pb[0] < 0x1000000) e_ = pb[0]; } catch { }
        }

        // ---- recover modulus ----
        var regions = ModuleRegions(baseAddr, 0x400000);
        BigInteger n = BigInteger.Zero;
        int nOff = -1;
        foreach (var kv in regions)
        {
            byte[] buf = kv.Value;
            for (int off = 0; off + keyBytes <= buf.Length; off += 4)
            {
                if ((buf[off] & 1) == 0) continue;                 // modulus is odd (little-endian low byte)
                BigInteger cand = BI(Slice(buf, off, keyBytes));
                if (BitLen(cand) != keyBytes * 8 || cand <= s) continue;
                if (BigInteger.ModPow(s, e_, cand) == m) { n = cand; nOff = kv.Key + off; break; }
                byte[] rev = Slice(buf, off, keyBytes); Array.Reverse(rev);
                BigInteger cand2 = BI(rev);
                if (BitLen(cand2) == keyBytes * 8 && cand2 > s && BigInteger.ModPow(s, e_, cand2) == m) { n = cand2; nOff = kv.Key + off; break; }
            }
            if (nOff >= 0) break;
        }
        if (nOff < 0)
        {
            // e might differ - try the usual suspects before giving up
            foreach (uint ce in new uint[] { 65537, 3, 17, 257, 0x10001 })
            {
                if (ce == e_) continue;
                foreach (var kv in regions)
                {
                    byte[] buf = kv.Value;
                    for (int off = 0; off + keyBytes <= buf.Length; off += 4)
                    {
                        if ((buf[off] & 1) == 0) continue;
                        BigInteger cand = BI(Slice(buf, off, keyBytes));
                        if (BitLen(cand) != keyBytes * 8 || cand <= s) continue;
                        if (BigInteger.ModPow(s, ce, cand) == m) { n = cand; nOff = kv.Key + off; e_ = ce; break; }
                    }
                    if (nOff >= 0) break;
                }
                if (nOff >= 0) break;
            }
        }
        // last resort: scan the file image (some builds keep N in a read-only page
        // that the memory walk skipped)
        if (nOff < 0)
        {
            foreach (Sec sc in secs)
            {
                if ((sc.Name != ".rdata" && sc.Name != ".data" && sc.Name != ".text") || sc.RawPtr <= 0) continue;
                int len = Math.Min(sc.RawSize, sc.VSize > 0 ? sc.VSize : sc.RawSize);
                for (int off = 0; off + keyBytes <= len; off += 4)
                {
                    int p = sc.RawPtr + off;
                    if (p + keyBytes > file.Length) break;
                    if ((file[p] & 1) == 0) continue;
                    BigInteger cand = BI(Slice(file, p, keyBytes));
                    if (BitLen(cand) != keyBytes * 8 || cand <= s) continue;
                    if (BigInteger.ModPow(s, e_, cand) == m) { n = cand; nOff = sc.VA + off; break; }
                }
                if (nOff >= 0) break;
            }
        }
        if (nOff < 0) { Console.WriteLine("modulus not found in module memory"); return 4; }
        Console.WriteLine("public exponent e = {0}", e_);
        Console.WriteLine("modulus recovered (offset 0x{0:X}): {1} bits", nOff, BitLen(n));

        // ---- locate the limb-multiply hook site (never trust a hardcoded RVA) ----
        int[] limbPat = SigPatterns.Compile(SigPatterns.LimbSite);
        int limbOff = SigPatterns.LimbSiteCallOffset;
        int site = 0, target = 0;

        if (hookRva != 0 && allmulRva != 0)
        {
            int chk = Rva2Off(secs, hookRva - limbOff);
            if (chk >= 0 && SiteMatches(file, chk, limbPat))
            {
                site = hookRva; target = baseAddr + allmulRva;
                Console.WriteLine("hook site RVA 0x{0:X} (from command line, fingerprint ok)", site);
            }
        }
        if (site == 0)
        {
            foreach (Sec sc in secs)
            {
                if (sc.Name != ".text" || sc.RawPtr <= 0) continue;
                int len = Math.Min(sc.RawSize, sc.VSize > 0 ? sc.VSize : sc.RawSize);
                foreach (int off in FindPattern(file, limbPat, sc.RawPtr, len))
                {
                    int rva = sc.VA + (off - sc.RawPtr) + limbOff;
                    int cOff = Rva2Off(secs, rva);
                    if (cOff < 0 || file[cOff] != 0xE8) continue;
                    int rel = BitConverter.ToInt32(file, cOff + 1);
                    int trva = rva + 5 + rel;
                    int tOff = Rva2Off(secs, trva);
                    if (tOff < 0) continue;
                    byte[] pro = Slice(file, tOff, 8);
                    bool okPrologue = pro[0] == 0x8B && pro[1] == 0x44 && pro[2] == 0x24 && pro[3] == 0x08 &&
                                      pro[4] == 0x8B && pro[5] == 0x4C && pro[6] == 0x24 && pro[7] == 0x10;
                    Console.WriteLine("  limb-site fingerprint hit RVA 0x{0:X} -> call 0x{1:X} ({2})",
                        rva, trva, okPrologue ? "prologue ok" : "prologue UNEXPECTED");
                    if (site == 0 && okPrologue) { site = rva; target = baseAddr + trva; }
                }
            }
        }
        if (site == 0)
        {
            Console.WriteLine("limb-multiply site not found - run Pre-flight and type its RVA");
            return 4;
        }
        if (hookRva != 0 && hookRva != site)
            Console.WriteLine("note: RVA 0x{0:X} from the command line is wrong for this build, using 0x{1:X}", hookRva, site);
        Console.WriteLine("hook site 0x{0:X8} -> call 0x{1:X8}", baseAddr + site, target);

        // ---- record limb-multiply operands ----
        int maxOps = 300000;
        g_buf = Marshal.AllocHGlobal(maxOps * 8 + 64);
        g_cnt = Marshal.AllocHGlobal(8);
        Marshal.WriteInt32(g_cnt, 0);
        IntPtr stub = VirtualAlloc(IntPtr.Zero, 512, 0x3000, 0x40);
        byte[] code = BuildStub(g_buf.ToInt32(), g_cnt.ToInt32(), target, baseAddr + site + 5, stub.ToInt32(), maxOps);
        CopyMemory(stub, code, (uint)code.Length);

        uint old;
        int patchAt = baseAddr + site;
        VirtualProtect((IntPtr)patchAt, 16, 0x40, out old);
        byte[] jmp = new byte[5];
        jmp[0] = 0xE9;
        int relj = stub.ToInt32() - (patchAt + 5);
        jmp[1] = (byte)relj; jmp[2] = (byte)(relj >> 8); jmp[3] = (byte)(relj >> 16); jmp[4] = (byte)(relj >> 24);
        CopyMemory((IntPtr)patchAt, jmp, 5);
        VirtualProtect((IntPtr)patchAt, 16, old, out old);

        sz = 1024;
        int count = 0;
        try
        {
            hr = CallSign(signFp, cc, hash, dst, ref sz);
            count = Marshal.ReadInt32(g_cnt);
        }
        catch (SEHException se)
        {
            Console.WriteLine("[-] fault inside the traced signing call (0x" + se.ErrorCode.ToString("X8") + ")");
            Console.WriteLine("  -> hook site 0x" + site.ToString("X") + " is not a limb multiply in this build");
            count = Marshal.ReadInt32(g_cnt);
            if (count <= 0) return 5;
        }
        int keep = Math.Min(count, maxOps);
        byte[] all = new byte[keep * 8];
        Marshal.Copy(g_buf, all, 0, all.Length);
        File.WriteAllBytes(Path.Combine(outDir, "ops.bin"), all);
        Console.WriteLine("hr={0} ops recorded={1}{2}", hr, count, count > maxOps ? " (truncated to " + maxOps + ")" : "");

        var sb = new StringBuilder();
        sb.Append("{\n");
        sb.Append("  \"dll\": \"").Append(dll.Replace("\\", "\\\\")).Append("\",\n");
        sb.Append("  \"export\": \"").Append(signName).Append("\",\n");
        sb.Append("  \"hash\": \"").Append(Hex(hash)).Append("\",\n");
        sb.Append("  \"signature\": \"").Append(Hex(Slice(dst, 0, keyBytes))).Append("\",\n");
        sb.Append("  \"e\": ").Append(e_).Append(",\n");
        sb.Append("  \"n\": \"").Append(n.ToString("x")).Append("\",\n");
        sb.Append("  \"ops\": ").Append(keep).Append("\n");
        sb.Append("}\n");
        File.WriteAllText(Path.Combine(outDir, "meta.json"), sb.ToString());
        Console.WriteLine("wrote meta.json + ops.bin to " + outDir);
        return 0;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int PubFnStd(uint[] buf, ref uint size);

    static int ParseHex(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0;
        s = s.Trim();
        if (s.StartsWith("0x") || s.StartsWith("0X")) s = s.Substring(2);
        int v;
        return int.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out v) ? v : 0;
    }

    static int BitLen(BigInteger v)
    {
        if (v.IsZero) return 0;
        byte[] b = v.ToByteArray();
        int i = b.Length - 1;
        while (i > 0 && b[i] == 0) i--;
        int bits = i * 8;
        byte top = b[i];
        while (top > 0) { bits++; top >>= 1; }
        return bits;
    }

    static byte[] Slice(byte[] b, int off, int len)
    {
        byte[] r = new byte[len];
        Array.Copy(b, off, r, 0, len);
        return r;
    }

    static string Hex(byte[] b)
    {
        var sb = new StringBuilder(b.Length * 2);
        foreach (byte x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }
}
