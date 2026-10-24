# -*- coding: utf-8 -*-
"""
keyhunter_ida.py -- KeyHunter from inside IDA (idapython, IDA 7.x / 8.x / 9.x)

What it does
    stage 1 (IDA)  locate the RSA signer and the Montgomery limb-multiply site
                   in the loaded module -- by export name first, then by the
                   build-stable byte fingerprints from SigPatterns.cs
    stage 2 (host) run the matching KeyHunter collector with the located RVA,
                   then analyze.py, and print / save the recovered private key

Why stage 2 exists
    The private exponent is NOT stored in the image: the signer hands
    obfuscated constants to an inner dispatcher, and a full scan of the data
    sections finds no d (and no p/q dividing n). The key therefore has to be
    recovered from the limb-multiplication trace, which is what the collectors
    do. This script automates locating + collecting + analysing.

Usage
    File > Script file... (Alt+F7) > keyhunter_ida.py
        -> runs automatically: prints the report, then starts the extraction
           in a background thread (IDA stays responsive).
    or in the IDA Python console:
        import keyhunter_ida as K
        K.report()          # locate only -- never executes the target
        K.extract()         # locate + collect + analyse (blocking)
        K.extract_async()   # same, but in a background thread

Everything is echoed to:
    * the IDA output window (opened automatically)
    * <outdir>/ida_keyhunter.log   (default E:\\project\\keyhunter_out)
"""

import os
import re
import sys
import json
import struct
import shutil
import threading
import traceback
import subprocess

import idaapi
import ida_bytes
import ida_entry
import ida_kernwin
import ida_nalt

try:                       # IDA 8/9
    import ida_ida
    import ida_funcs
except ImportError:        # IDA 7.x
    ida_ida = None
    import ida_funcs

# ----------------------------------------------------------------- patterns --
# same fingerprints as SigPatterns.cs (?? = wildcard byte)
SIGNER_PATTERN = (
    "8B FF 55 8B EC 51 51 57 8D 45 FC 50 8D 45 F8 50 E8 ?? ?? ?? ?? "
    "8B 7D 18 8B 45 FC 39 07 73 07 B8 57 00 07 80 EB 4A 56 8B 75 14 56 51 FF 75 10 "
    "C6 44 30 FF 00 FF 75 0C 8B 4D FC E8 ?? ?? ?? ?? 85 C0 74 0C 7E 2A 0F B7 C0 "
    "0D 00 00 07 80 EB 20 56 56 E8 ?? ?? ?? ?? 85 C0 75 07 B8 0E 00 07 80 EB"
)
LIMB_PATTERN = (
    "E8 ?? ?? ?? ?? 4C 10 AE 8B 44 24 2C FF 30 E8 ?? ?? ?? ?? 8B 4C 24 40 03 C7 8B DA 8B"
)
LIMB_CALL_OFFSET = 14      # offset of the "call __allmul" inside LIMB_PATTERN

# ------------------------------------------------------------------- config --
# directory holding KeyHunter.exe / KeyHunterExe.exe / analyze.py
TOOLS_DIR = os.environ.get("KEYHUNTER_TOOLS", r"E:\project\SignPKCS\KeyHunterGui\bin\Release")
HOLD_MS = "8000"           # how long the EXE collector keeps the target alive
PUB_E = "65537"
# set KEYHUNTER_AUTO_EXTRACT=0 to only print the report on load
AUTO_EXTRACT = os.environ.get("KEYHUNTER_AUTO_EXTRACT", "1") not in ("0", "no", "off", "")
LOG_FILE = os.path.join(os.environ.get("KEYHUNTER_OUT", r"E:\project\keyhunter_out"),
                        "ida_keyhunter.log")

# ------------------------------------------------------------ logging infra --
_LOGQ = []                 # lines produced by the background thread
_DONE = threading.Event()
_LOG_LOCK = threading.Lock()
_LOG_FP = [None]
_AUTO_RAN = [False]
_TIMER = [None]


def _emit(msg):
    """Print on the main thread only: IDA msg + stdout + log file."""
    s = str(msg)
    try:
        ida_kernwin.msg(s + "\n")
    except Exception:
        pass
    try:
        print(s)
    except Exception:
        pass
    try:
        if _LOG_FP[0] is None:
            d = os.path.dirname(LOG_FILE)
            if d:
                os.makedirs(d, exist_ok=True)
            _LOG_FP[0] = open(LOG_FILE, "w", encoding="utf-8", errors="replace")
        _LOG_FP[0].write(s + "\n")
        _LOG_FP[0].flush()
    except Exception:
        pass


def _background():
    try:
        return threading.current_thread() is not threading.main_thread()
    except Exception:
        return False


def log(msg=""):
    """Thread-safe logging: from the worker thread the lines are queued and
    flushed into IDA by a timer, so the IDA UI never blocks."""
    if _background():
        with _LOG_LOCK:
            _LOGQ.append(str(msg))
        return
    _emit(msg)


def _pump():
    """IDA timer: drain the queue into the output window."""
    try:
        while True:
            with _LOG_LOCK:
                if not _LOGQ:
                    break
                m = _LOGQ.pop(0)
            _emit(m)
    except Exception:
        pass
    if _DONE.is_set():
        with _LOG_LOCK:
            if not _LOGQ:
                try:
                    ida_kernwin.unregister_timer(_TIMER[0])
                except Exception:
                    pass
                _TIMER[0] = None
                return -1
    return 100


def _start_pump():
    if _TIMER[0] is not None:
        return
    try:
        _TIMER[0] = ida_kernwin.register_timer(100, _pump)
    except Exception:
        pass


def show_output():
    """Make sure the 'Output window' subview is visible."""
    for name in ("show_output_window", "open_output_window", "display_output_window"):
        fn = getattr(ida_kernwin, name, None)
        if callable(fn):
            try:
                fn()
                return
            except Exception:
                pass
    try:
        ida_kernwin.process_ui_action("msgWindow")
    except Exception:
        pass


# --------------------------------------------------------------- ida shims ---
def min_ea():
    if ida_ida:
        return ida_ida.inf_get_min_ea()
    return idaapi.get_inf_structure().min_ea


def max_ea():
    if ida_ida:
        return ida_ida.inf_get_max_ea()
    return idaapi.get_inf_structure().max_ea


def is_64bit():
    try:
        if ida_ida:
            return ida_ida.inf_is_64bit()
        return idaapi.get_inf_structure().is_64bit()
    except Exception:
        return False


def image_base():
    try:
        return ida_nalt.get_imagebase()
    except Exception:
        return idaapi.get_imagebase()


def target_path():
    try:
        return ida_nalt.get_input_file_path()
    except Exception:
        try:
            return idaapi.get_input_file_path()
        except Exception:
            return ""


def rva(ea):
    return ea - image_base()


def name_at(ea):
    try:
        return ida_funcs.get_func_name(ea) or ("sub_%X" % ea)
    except Exception:
        return "sub_%X" % ea


# ------------------------------------------------------------ byte searching --
def _pat_to_list(pattern):
    return [-1 if p == "??" else int(p, 16) for p in pattern.split()]


def _scan_fallback(pattern):
    """Pure-python search over the whole image: slower but works on every IDA
    version and does not depend on compiled_binpat_vec_t being available."""
    pat = _pat_to_list(pattern)
    n = len(pat)
    lo, hi = min_ea(), max_ea()
    out = []
    chunk = 0x40000
    ea = lo
    while ea < hi:
        size = min(chunk, hi - ea)
        buf = ida_bytes.get_bytes(ea, size)
        if not buf:
            break
        for i in range(0, max(0, len(buf) - n + 1)):
            ok = True
            for j in range(n):
                b = pat[j]
                if b >= 0 and buf[i + j] != b:
                    ok = False
                    break
            if ok:
                out.append(ea + i)
        ea += size - n + 1 if size >= n else size
    return out


def find_bytes(pattern):
    """IDA binary search with ?? wildcards -> list of EAs."""
    hits = []
    try:
        pat = ida_bytes.compiled_binpat_vec_t()
        start = min_ea()
        if ida_bytes.parse_binpat_str(pat, start, pattern, 16):
            ea, end, bad = start, max_ea(), idaapi.BADADDR
            while ea < end:
                ea = ida_bytes.bin_search(ea, end, pat, ida_bytes.BIN_SEARCH_FORWARD)
                if ea == bad or ea == 0xFFFFFFFFFFFFFFFF:
                    break
                hits.append(ea)
                ea += 1
    except Exception as e:
        log("  [i] ida binary search unavailable (%s), using fallback scan" % e)
    if not hits:
        hits = _scan_fallback(pattern)
    return hits


def exports():
    out = []
    try:
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            nm = ida_entry.get_entry_name(ordinal)
            if ea and ea != idaapi.BADADDR:
                out.append((ea, nm or ""))
    except Exception:
        pass
    return out


# ------------------------------------------------------------------ stage 1 --
def find_signer():
    """-> list of (ea, name, how)"""
    found = []
    for ea, nm in exports():
        up = (nm or "").upper()
        if "SIGN" in up or "PKCS" in up:
            found.append((ea, nm, "export"))
    for ea in find_bytes(SIGNER_PATTERN):
        found.append((ea, name_at(ea), "fingerprint"))
    seen = set()
    uniq = []
    for ea, nm, how in sorted(found, key=lambda x: (x[2] != "export", x[0])):
        if ea in seen:
            continue
        seen.add(ea)
        uniq.append((ea, nm, how))
    return uniq


def find_limb_site():
    """-> list of (site_ea, call_target_ea); site_ea is the 'call __allmul'."""
    out = []
    for ea in find_bytes(LIMB_PATTERN):
        site = ea + LIMB_CALL_OFFSET
        if ida_bytes.get_bytes(site, 1) != b"\xE8":
            continue
        rel_bytes = ida_bytes.get_bytes(site + 1, 4)
        if not rel_bytes or len(rel_bytes) != 4:
            continue
        rel = struct.unpack("<i", rel_bytes)[0]
        tgt = (site + 5 + rel) & 0xFFFFFFFF
        out.append((site, tgt))
    return out


def report():
    """Locate the signer and the limb site. Never executes the target."""
    path = target_path()
    log("=" * 66)
    log("KeyHunter / IDA  -  " + (path or "?"))
    log("ida python " + sys.version.split()[0])
    if is_64bit():
        log("[!] 64-bit image: limb tracing is not implemented, stop here.")
        return None
    log("image base 0x%X   range 0x%X..0x%X" % (image_base(), min_ea(), max_ea()))

    signers = find_signer()
    if signers:
        for ea, nm, how in signers:
            log("signer      0x%X  rva 0x%X  %-14s (%s)" % (ea, rva(ea), nm, how))
    else:
        log("[!] signer not found (no matching export, no fingerprint hit)")

    sites = find_limb_site()
    if sites:
        for site, tgt in sites:
            pro = ida_bytes.get_bytes(tgt, 8)
            ok = pro == b"\x8B\x44\x24\x08\x8B\x4C\x24\x10"
            log("limb site   0x%X  rva 0x%X  -> call 0x%X (%s)"
                % (site, rva(site), tgt, "prologue ok" if ok else "prologue UNEXPECTED"))
    else:
        log("[!] limb-multiply site not found")

    if not (signers and sites):
        log("=" * 66)
        return None
    log("=" * 66)
    return {"path": path, "signer": signers[0], "site": sites[0]}


# ------------------------------------------------------------------ stage 2 --
def _tools_dir():
    here = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else ""
    cands = [
        TOOLS_DIR,
        here,
        os.path.join(here, "..", "bin", "Release"),
        os.path.join(here, "..", "..", "bin", "Release"),
        os.path.join(here, "..", "tools"),
    ]
    for c in cands:
        try:
            if c and os.path.isdir(c) and os.path.isfile(os.path.join(c, "analyze.py")):
                return os.path.abspath(c)
        except Exception:
            pass
    return None


def _python_exe():
    cands = [os.environ.get("KEYHUNTER_PYTHON"),
             r"C:\Users\bkkmm\.workbuddy\binaries\python\versions\3.13.12\python.exe"]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    for c in ("python", "py"):
        p = shutil.which(c)
        if p:
            return p
    return "python"


def _run(cmd, cwd, tag):
    log("")
    log("$ " + " ".join(('"%s"' % c if " " in c else c) for c in cmd))
    try:
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, universal_newlines=True,
                             errors="replace")
    except Exception as e:
        log("[!] cannot start %s: %s" % (tag, e))
        return 1
    try:
        for line in p.stdout:
            log("    " + line.rstrip("\r\n"))
    except Exception:
        pass
    p.wait()
    return p.returncode


def extract(out_dir=None, info=None):
    """Locate (main thread) then collect + analyse."""
    if info is None:
        info = report()
    if not info:
        return 1
    return _collect(info["path"], "%X" % rva(info["site"][0]), out_dir)


def _collect(path, site_rva, out_dir=None):
    """Subprocess stage. Touches NO ida_* API, so it may run on a worker
    thread -- IDA >= 9 refuses ida_* calls from anywhere but the main one."""
    tools = _tools_dir()
    if not tools:
        log("[!] tools directory not found (KeyHunter.exe / analyze.py).")
        log("    set KEYHUNTER_TOOLS or edit TOOLS_DIR at the top of this script.")
        return 1
    log("tools       " + tools)

    if not path or not os.path.isfile(path):
        log("[!] cannot resolve the input file path: %r" % path)
        return 1
    if out_dir is None:
        out_dir = os.environ.get("KEYHUNTER_OUT",
                                 os.path.join(os.path.dirname(path), "keyhunter_out"))
    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        pass

    is_dll = path.lower().endswith(".dll")

    if is_dll:
        # KeyHunter.exe loads the DLL in-process (auto-detected export + site)
        cmd = [os.path.join(tools, "KeyHunter.exe"), path, out_dir, site_rva, "0", "auto"]
    else:
        # KeyHunterExe.exe spawns the EXE and calls the signer directly
        cmd = [os.path.join(tools, "KeyHunterExe.exe"), path, out_dir, site_rva, PUB_E, HOLD_MS]

    rc = _run(cmd, tools, "collector")
    if rc != 0:
        log("[!] collector failed (exit %d)" % rc)
        return rc

    rc = _run([_python_exe(), os.path.join(tools, "analyze.py"), out_dir], tools, "analyzer")
    if rc != 0:
        log("[!] analyzer failed (exit %d)" % rc)
        return rc

    key_txt = os.path.join(out_dir, "KEY.txt")
    if os.path.isfile(key_txt):
        log("")
        try:
            raw = open(key_txt, "rb").read()
            txt = None
            for enc in ("utf-8", "gbk", "mbcs", "latin-1"):
                try:
                    txt = raw.decode(enc)
                    break
                except Exception:
                    continue
            if txt:
                log(txt)
        except Exception:
            pass
    try:
        meta = json.load(open(os.path.join(out_dir, "meta.json")))
        n = int(meta["n"], 16)
        log("modulus n = %d bits" % n.bit_length())
    except Exception:
        pass
    for f in ("private_pkcs1.pem", "private_pkcs8.pem", "ops.bin"):
        p = os.path.join(out_dir, f)
        if os.path.isfile(p):
            log("%-18s %s (%d bytes)" % (f, p, os.path.getsize(p)))
    log("")
    log("[+] key written to " + out_dir)
    log("[+] full log: " + LOG_FILE)
    return 0


def extract_async(out_dir=None, info=None):
    """Run the collection + analysis in a worker thread so IDA stays usable.
    Stage 1 (IDA API) is done here on the main thread; the worker only runs
    subprocesses, because IDA >= 9 rejects ida_* calls off the main thread."""
    if info is None:
        info = report()
    if not info:
        return None
    path = info["path"]
    site_rva = "%X" % rva(info["site"][0])

    _DONE.clear()
    _start_pump()

    def worker():
        try:
            _collect(path, site_rva, out_dir)
        except Exception:
            log(traceback.format_exc())
        finally:
            _DONE.set()

    t = threading.Thread(target=worker)
    t.daemon = True
    t.start()
    log("[i] extraction running in the background - watch this window")
    return t


def main():
    return extract()


# ------------------------------------------------------------------- on load --
def _auto_run():
    """Runs on Alt+F7 / exec. IDA does not guarantee __name__ == '__main__',
    so this is called unconditionally from the module body."""
    if _AUTO_RAN[0]:
        return
    _AUTO_RAN[0] = True
    try:
        show_output()
        info = report()
    except Exception:
        log("[!] report() crashed:")
        log(traceback.format_exc())
        return
    if not info:
        log("[i] nothing to extract - fix the pattern hits above first")
        return
    if not AUTO_EXTRACT:
        log("[i] auto-extract disabled; run  keyhunter_ida.extract_async()  "
            "in the console to collect the key")
        return

    # default path: run synchronously on the main thread. IDA >= 9 refuses
    # ida_* calls off the main thread, and the collect/analyse stage is just
    # subprocesses, so blocking here (with a wait box) is the safest option.
    try:
        ida_kernwin.show_wait_box("KeyHunter: collecting the trace, please wait...")
    except Exception:
        pass
    try:
        extract(info=info)
    except Exception:
        log("[!] extraction crashed:")
        log(traceback.format_exc())
    finally:
        try:
            ida_kernwin.hide_wait_box()
        except Exception:
            pass


_auto_run()

if __name__ == "__main__":
    # already handled by _auto_run(); kept for direct python execution
    pass
