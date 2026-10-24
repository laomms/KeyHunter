using System;
using System.Collections.Generic;

// Build-stable fingerprints for the SignPKCS signer.
//
// Both patterns were derived by diffing two independent builds (SignPKCS.dll and
// SignPKCSExe.exe) built from the same Main.asm: every byte that differed between
// them was turned into a wildcard, so the remaining fixed bytes are the ones that
// survive relinking. Each pattern matches exactly once in both binaries.
//
// SignerFunc: 96 bytes, 84 fixed. Anchors VRSAVaultSignPKCS (ecx/edi prologue plus
//             the GetPubParams call and the buffer-size check with E_INVALIDARG).
// LimbSite:   28 bytes, 20 fixed. Anchors the "mov eax,[esp+2Ch]; push [eax]; call
//             __allmul" sequence that feeds the Montgomery limb multiply.
public static class SigPatterns
{
    public const string SignerFunc =
        "8B FF 55 8B EC 51 51 57 8D 45 FC 50 8D 45 F8 50 E8 ?? ?? ?? ?? " +
        "8B 7D 18 8B 45 FC 39 07 73 07 B8 57 00 07 80 EB 4A 56 8B 75 14 56 51 FF 75 10 " +
        "C6 44 30 FF 00 FF 75 0C 8B 4D FC E8 ?? ?? ?? ?? 85 C0 74 0C 7E 2A 0F B7 C0 " +
        "0D 00 00 07 80 EB 20 56 56 E8 ?? ?? ?? ?? 85 C0 75 07 B8 0E 00 07 80 EB";

    public const string LimbSite =
        "E8 ?? ?? ?? ?? 4C 10 AE 8B 44 24 2C FF 30 E8 ?? ?? ?? ?? 8B 4C 24 40 03 C7 8B DA 8B";

    // offset of the limb-multiply "call" inside LimbSite
    public const int LimbSiteCallOffset = 14;

    public static int[] Compile(string hex)
    {
        string[] parts = hex.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        int[] pat = new int[parts.Length];
        for (int i = 0; i < parts.Length; i++)
            pat[i] = parts[i] == "??" ? -1 : Convert.ToInt32(parts[i], 16);
        return pat;
    }

    public static List<int> FindAll(byte[] data, int start, int length, int[] pat)
    {
        var hits = new List<int>();
        int end = start + length - pat.Length;
        for (int i = start; i <= end; i++)
        {
            bool ok = true;
            for (int j = 0; j < pat.Length; j++)
            {
                if (pat[j] >= 0 && data[i + j] != pat[j]) { ok = false; break; }
            }
            if (ok) hits.Add(i);
        }
        return hits;
    }

    public static int FixedBytes(int[] pat)
    {
        int n = 0;
        foreach (int b in pat) if (b >= 0) n++;
        return n;
    }
}
