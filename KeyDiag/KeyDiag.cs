using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Windows.Forms;

// KeyDiag - static pre-flight for KeyHunter: tells you whether a target is a
// suitable 32-bit native PE and whether the hook patterns exist.
class KeyDiag
{
    class Sec
    {
        public string Name; public int Va, Vs, Rp, Rs;
    }

    static int U16(byte[] d, int o) { return BitConverter.ToUInt16(d, o); }
    static int U32(byte[] d, int o) { return (int)BitConverter.ToUInt32(d, o); }

    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length >= 1)
        {
            foreach (string line in BuildReport(Path.GetFullPath(args[0]))) Console.WriteLine(line);
            return;
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new KeyDiagForm());
    }

    static string RvaList(List<int> hits, int textVa)
    {
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < hits.Count && i < 4; i++)
        {
            if (i > 0) sb.Append(", ");
            sb.Append("0x").Append((textVa + hits[i]).ToString("X"));
        }
        return sb.ToString();
    }

    // Lists call sites whose target looks like a small multiply helper: a short
    // function containing a MUL instruction (F7 /4). On both x86 and x64 the
    // 64-bit multiply helper has exactly this shape, and its callers are the
    // places worth hooking.
    static void ScanCandidates(byte[] text, int textVa, int max)
    {
        var byTarget = new Dictionary<int, List<int>>();
        for (int i = 0; i + 5 <= text.Length; i++)
        {
            if (text[i] != 0xE8) continue;
            int rel = BitConverter.ToInt32(text, i + 1);
            int tgt = i + 5 + rel;
            if (tgt <= 0 || tgt >= text.Length) continue;
            List<int> l;
            if (!byTarget.TryGetValue(tgt, out l)) { l = new List<int>(); byTarget[tgt] = l; }
            l.Add(i);
        }

        var rows = new List<string[]>();
        foreach (KeyValuePair<int, List<int>> kv in byTarget)
        {
            int tgt = kv.Key;
            int size = -1;
            for (int j = tgt; j < Math.Min(tgt + 192, text.Length); j++) if (text[j] == 0xC3) { size = j - tgt + 1; break; }
            if (size < 0 || size > 160) continue;

            bool hasMul = false;
            for (int j = tgt; j < tgt + size - 1; j++)
            {
                byte b = text[j];
                if (b == 0xF7 || b == 0xF6)
                {
                    byte modrm = text[j + 1];
                    if (((modrm >> 3) & 7) == 4) { hasMul = true; break; }   // /4 = MUL
                }
            }
            if (!hasMul) continue;

            int callSite = kv.Value[0];
            string pro = BitConverter.ToString(text, tgt, Math.Min(6, text.Length - tgt)).Replace("-", " ");
            rows.Add(new string[] {
                "0x" + (textVa + callSite).ToString("X"),
                "0x" + (textVa + tgt).ToString("X"),
                size.ToString(), kv.Value.Count.ToString(), pro });
        }

        rows.Sort(delegate (string[] a, string[] b) { return a[2].CompareTo(b[2]); });
        Out("");
        Out("candidate hook sites (call -> small function containing MUL):");
        if (rows.Count == 0) { Out("  none found"); return; }
        Out(string.Format("  {0,-12} {1,-12} {2,-6} {3,-6} {4}", "call RVA", "target RVA", "size", "callers", "target prologue"));
        int n = 0;
        foreach (string[] r in rows)
        {
            Out(string.Format("  {0,-12} {1,-12} {2,-6} {3,-6} {4}", r[0], r[1], r[2], r[3], r[4]));
            if (++n >= max) break;
        }
        Out("  -> use the 'call RVA' column as the Site RVA");
    }

    static int RvaToOff(List<Sec> secs, int rva)
    {
        foreach (Sec s in secs)
            if (rva >= s.Va && rva < s.Va + Math.Max(s.Vs, s.Rs)) return s.Rp + (rva - s.Va);
        return -1;
    }

    static void Check(byte[] d, List<Sec> secs, string label, string hex)
    {
        byte[] pat = new byte[hex.Length / 2];
        for (int i = 0; i < pat.Length; i++) pat[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        var hits = new List<string>();
        foreach (Sec s in secs)
        {
            if (s.Name != ".text") continue;
            int end = Math.Min(s.Rp + s.Rs, d.Length);
            for (int i = s.Rp; i + pat.Length <= end; i++)
            {
                bool ok = true;
                for (int j = 0; j < pat.Length; j++) if (d[i + j] != pat[j]) { ok = false; break; }
                if (ok && hits.Count < 4) hits.Add("0x" + (s.Va + (i - s.Rp)).ToString("X"));
            }
        }
        Out(string.Format("{0,-38}: {1}", label,
            hits.Count == 0 ? "NOT FOUND" : string.Join(", ", hits.ToArray())));
    }

    static List<string> g_lines;

    static void Out(string s)
    {
        if (g_lines != null) g_lines.Add(s); else Out(s);
    }

    public static List<string> BuildReport(string path)
    {
        g_lines = new List<string>();
        Analyze(path);
        List<string> r = g_lines; g_lines = null; return r;
    }

    static void Analyze(string path)
    {
        if (!File.Exists(path)) { Out("not found: " + path); return; }
        byte[] d = File.ReadAllBytes(path);
        Out("file      : " + path);
        Out("size      : " + d.Length);

        int lfanew = U32(d, 0x3C);
        int machine = U16(d, lfanew + 4);
        int nsec = U16(d, lfanew + 6);
        int optSize = U16(d, lfanew + 20);
        int characteristics = U16(d, lfanew + 22);
        bool pe32plus = U16(d, lfanew + 24) == 0x20B;
        int subsystem = U16(d, lfanew + 24 + 68);
        int entry = U32(d, lfanew + 24 + 16);
        long imageBase = pe32plus ? (long)BitConverter.ToUInt64(d, lfanew + 24 + 24) : (long)U32(d, lfanew + 24 + 28);

        string machName = machine == 0x14C ? "x86 (32-bit)" : machine == 0x8664 ? "x64 (64-bit)" : ("0x" + machine.ToString("X"));
        Out("machine   : " + machName);
        Out("subsystem : " + subsystem + (subsystem == 3 ? " (console)" : subsystem == 2 ? " (GUI)" : ""));
        Out("entry RVA : 0x" + entry.ToString("X"));
        Out("image base: 0x" + imageBase.ToString("X"));
        Out("is DLL    : " + ((characteristics & 0x2000) != 0));

        var secs = new List<Sec>();
        int off = lfanew + 24 + optSize;
        for (int i = 0; i < nsec; i++)
        {
            Sec s = new Sec();
            s.Name = Encoding.ASCII.GetString(d, off, 8).TrimEnd('\0');
            s.Vs = U32(d, off + 8); s.Va = U32(d, off + 12);
            s.Rs = U32(d, off + 16); s.Rp = U32(d, off + 20);
            secs.Add(s);
            off += 40;
        }
        var names = new List<string>();
        foreach (Sec s in secs) names.Add(s.Name);
        Out("sections  : " + string.Join(", ", names.ToArray()));

        var dlls = new List<string>();
        int impRva = U32(d, lfanew + 24 + (pe32plus ? 112 : 104));
        if (impRva != 0)
        {
            int pos = RvaToOff(secs, impRva);
            if (pos > 0)
                for (int i = 0; i < 32; i++)
                {
                    int nameRva = U32(d, pos + i * 20 + 12);
                    if (nameRva == 0) break;
                    int np = RvaToOff(secs, nameRva);
                    if (np <= 0) break;
                    int e = np; while (e < d.Length && d[e] != 0) e++;
                    dlls.Add(Encoding.ASCII.GetString(d, np, e - np));
                }
        }
        Out("imports   : " + string.Join(", ", dlls.ToArray()));
        bool dotnet = dlls.Contains("mscoree.dll");
        if (dotnet) Out("NOTE      : .NET assembly - not a native 32-bit signer");

        // strong, build-stable fingerprints (see SigPatterns.cs)
        int[] funcPat = SigPatterns.Compile(SigPatterns.SignerFunc);
        int[] sitePat = SigPatterns.Compile(SigPatterns.LimbSite);
        byte[] text = null; int textVa = 0;
        foreach (Sec s in secs) if (s.Name == ".text") { textVa = s.Va; text = new byte[Math.Min(s.Rs, d.Length - s.Rp)]; Array.Copy(d, s.Rp, text, 0, text.Length); }
        var fh = text == null ? new List<int>() : SigPatterns.FindAll(text, 0, text.Length, funcPat);
        var sh = text == null ? new List<int>() : SigPatterns.FindAll(text, 0, text.Length, sitePat);
        Out(string.Format("{0,-38}: {1}", "signer fingerprint (" + SigPatterns.FixedBytes(funcPat) + "/" + funcPat.Length + " fixed)",
            fh.Count == 0 ? "NOT FOUND" : fh.Count + " hit(s) @ " + RvaList(fh, textVa)));
        Out(string.Format("{0,-38}: {1}", "limb-site fingerprint (" + SigPatterns.FixedBytes(sitePat) + "/" + sitePat.Length + " fixed)",
            sh.Count == 0 ? "NOT FOUND" : sh.Count + " hit(s) @ " + RvaList(sh, textVa)));
        if (text != null) ScanCandidates(text, textVa, 20);
        if (fh.Count == 1 && sh.Count == 1)
        {
            int siteRva = textVa + sh[0] + SigPatterns.LimbSiteCallOffset;
            Out("verdict                                   : MATCH - site RVA = 0x" + siteRva.ToString("X"));
        }
        else if (fh.Count == 0)
            Out("verdict                                   : NOT the same signer (fingerprint absent)");
        else
            Out("verdict                                   : AMBIGUOUS - " + fh.Count + " signer hits, " + sh.Count + " site hits");
    }
}






