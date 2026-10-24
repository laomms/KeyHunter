using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Windows.Forms;
using System.Collections.Generic;

namespace KeyHunterGui
{
    public class MainForm : Form
    {
        TextBox txtTarget, txtOut, txtSite, txtE, txtHold;
        ComboBox cmbMode;
        RichTextBox rtb;
        Button btnBrowseT, btnBrowseO, btnPreflight, btnStart, btnOpen, btnClear;
        ToolStripStatusLabel lblStatus;
        bool running;

        public MainForm()
        {
            Text = "KeyHunter - RSA key extractor";
            Width = 980; Height = 680;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Consolas", 9f);

            var top = new TableLayoutPanel();
            top.Dock = DockStyle.Top;
            top.Height = 190;
            top.ColumnCount = 4;
            top.RowCount = 4;
            top.Padding = new Padding(8);
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
            top.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            top.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            top.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            top.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
            top.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            top.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            top.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            top.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));

            top.Controls.Add(new Label { Text = "Target:", TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill }, 0, 0);
            txtTarget = new TextBox { Dock = DockStyle.Fill };
            top.Controls.Add(txtTarget, 1, 0);
            btnBrowseT = new Button { Text = "Browse...", Dock = DockStyle.Fill };
            btnBrowseT.Click += btnBrowseTarget_Click;
            top.Controls.Add(btnBrowseT, 2, 0);
            top.SetColumnSpan(btnBrowseT, 2);

            top.Controls.Add(new Label { Text = "Output:", TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill }, 0, 1);
            txtOut = new TextBox { Dock = DockStyle.Fill };
            top.Controls.Add(txtOut, 1, 1);
            btnBrowseO = new Button { Text = "Browse...", Dock = DockStyle.Fill };
            btnBrowseO.Click += btnBrowseOut_Click;
            top.Controls.Add(btnBrowseO, 2, 1);
            top.SetColumnSpan(btnBrowseO, 2);

            var opt = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            opt.Controls.Add(new Label { Text = "Mode:", AutoSize = true, Padding = new Padding(0, 6, 4, 0) });
            cmbMode = new ComboBox { Width = 70, DropDownStyle = ComboBoxStyle.DropDownList };
            cmbMode.Items.AddRange(new object[] { "Auto", "DLL", "EXE", "x64" });
            cmbMode.SelectedIndex = 0;
            opt.Controls.Add(cmbMode);
            opt.Controls.Add(new Label { Text = "   Site RVA:", AutoSize = true, Padding = new Padding(0, 6, 4, 0) });
            txtSite = new TextBox { Width = 80, Text = "0" };
            opt.Controls.Add(txtSite);
            opt.Controls.Add(new Label { Text = "   e:", AutoSize = true, Padding = new Padding(0, 6, 4, 0) });
            txtE = new TextBox { Width = 70, Text = "65537" };
            opt.Controls.Add(txtE);
            opt.Controls.Add(new Label { Text = "   Hold(ms):", AutoSize = true, Padding = new Padding(0, 6, 4, 0) });
            txtHold = new TextBox { Width = 70, Text = "8000" };
            opt.Controls.Add(txtHold);
            top.Controls.Add(opt, 1, 2);
            top.SetColumnSpan(opt, 3);

            var btns = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
            btnPreflight = new Button { Text = "Pre-flight", Width = 90 };
            btnPreflight.Click += btnPreflight_Click;
            btnStart = new Button { Text = "Start", Width = 90 };
            btnStart.Click += btnStart_Click;
            btnOpen = new Button { Text = "Open output", Width = 100 };
            btnOpen.Click += btnOpen_Click;
            btnClear = new Button { Text = "Clear log", Width = 90 };
            btnClear.Click += delegate { rtb.Clear(); };
            btns.Controls.AddRange(new Control[] { btnPreflight, btnStart, btnOpen, btnClear });
            top.Controls.Add(btns, 1, 3);
            top.SetColumnSpan(btns, 3);

            rtb = new RichTextBox();
            rtb.Dock = DockStyle.Fill;
            rtb.ReadOnly = true;
            rtb.BackColor = Color.FromArgb(30, 30, 30);
            rtb.ForeColor = Color.Gainsboro;
            rtb.Font = new Font("Consolas", 9f);
            rtb.WordWrap = false;
            rtb.HideSelection = false;

            var status = new StatusStrip();
            lblStatus = new ToolStripStatusLabel("ready");
            status.Items.Add(lblStatus);

            Controls.Add(rtb);
            Controls.Add(top);
            Controls.Add(status);

            LogInfo("KeyHunter GUI ready.");
            LogInfo("Pick a target (DLL or EXE), then Pre-flight, then Start.");
        }

        // ---------------- logging ----------------
        void Append(string s, Color c)
        {
            if (rtb.InvokeRequired) { rtb.BeginInvoke((MethodInvoker)delegate { Append(s, c); }); return; }
            rtb.SelectionStart = rtb.TextLength;
            rtb.SelectionLength = 0;
            rtb.SelectionColor = c;
            rtb.AppendText(s + Environment.NewLine);
            rtb.SelectionColor = rtb.ForeColor;
            rtb.ScrollToCaret();
        }
        void LogInfo(string s) { Append("[*] " + s, Color.Gainsboro); }
        void LogOk(string s) { Append("[+] " + s, Color.LightGreen); }
        void LogWarn(string s) { Append("[!] " + s, Color.Orange); }
        void LogErr(string s) { Append("[-] " + s, Color.IndianRed); }
        void LogRaw(string s) { Append("    " + s, Color.Gray); }
        void SetStatus(string s)
        {
            if (InvokeRequired) { BeginInvoke((MethodInvoker)delegate { lblStatus.Text = s; }); return; }
            lblStatus.Text = s;
        }

        // ---------------- UI events ----------------
        void btnBrowseTarget_Click(object sender, EventArgs e)
        {
            var d = new OpenFileDialog();
            d.Filter = "PE files (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*";
            if (d.ShowDialog() == DialogResult.OK)
            {
                txtTarget.Text = d.FileName;
                if (txtOut.Text.Length == 0)
                    txtOut.Text = Path.Combine(Path.GetDirectoryName(d.FileName), "keyhunter_out");
            }
        }

        void btnBrowseOut_Click(object sender, EventArgs e)
        {
            var d = new FolderBrowserDialog();
            if (d.ShowDialog() == DialogResult.OK) txtOut.Text = d.SelectedPath;
        }

        void btnOpen_Click(object sender, EventArgs e)
        {
            string p = txtOut.Text.Trim();
            if (p.Length > 0 && Directory.Exists(p)) Process.Start("explorer.exe", "\"" + p + "\"");
        }

        void btnPreflight_Click(object sender, EventArgs e)
        {
            string t = txtTarget.Text.Trim();
            if (!File.Exists(t)) { LogErr("target not found: " + t); return; }
            Preflight(t);
        }

        void btnStart_Click(object sender, EventArgs e)
        {
            if (running) return;
            string t = txtTarget.Text.Trim();
            if (!File.Exists(t)) { LogErr("target not found: " + t); return; }
            string o = txtOut.Text.Trim();
            if (o.Length == 0) { LogErr("choose an output directory"); return; }
            running = true;
            btnStart.Enabled = btnPreflight.Enabled = false;

            // capture every UI value on the UI thread - the worker must not touch controls
            string mode = cmbMode.SelectedItem.ToString();
            string site = txtSite.Text.Trim();
            string pubE = txtE.Text.Trim();
            string hold = txtHold.Text.Trim();

            var th = new System.Threading.Thread(delegate () { RunAll(t, o, mode, site, pubE, hold); });
            th.IsBackground = true;
            th.Start();
        }

        // ---------------- static PE inspection (pre-flight) ----------------
        class Sec { public string Name; public int Va, Vs, Rp, Rs; }
        static int U16(byte[] d, int o) { return BitConverter.ToUInt16(d, o); }
        static int U32(byte[] d, int o) { return (int)BitConverter.ToUInt32(d, o); }
        static int RvaToOff(List<Sec> secs, int rva)
        {
            foreach (Sec s in secs)
                if (rva >= s.Va && rva < s.Va + Math.Max(s.Vs, s.Rs)) return s.Rp + (rva - s.Va);
            return -1;
        }

        static List<string> FindPattern(byte[] d, List<Sec> secs, string hex, int max)
        {
            var hits = new List<string>();
            byte[] pat = new byte[hex.Length / 2];
            for (int i = 0; i < pat.Length; i++) pat[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            foreach (Sec s in secs)
            {
                if (s.Name != ".text") continue;
                int end = Math.Min(s.Rp + s.Rs, d.Length);
                for (int i = s.Rp; i + pat.Length <= end; i++)
                {
                    bool ok = true;
                    for (int j = 0; j < pat.Length; j++) if (d[i + j] != pat[j]) { ok = false; break; }
                    if (ok) { hits.Add((s.Va + (i - s.Rp)).ToString("X")); if (hits.Count >= max) return hits; }
                }
            }
            return hits;
        }

        static List<string> ToRva(List<int> hits, int textVa)
        {
            var r = new List<string>();
            foreach (int h in hits) r.Add("0x" + (textVa + h).ToString("X"));
            return r;
        }

        void Preflight(string path)
        {
            LogInfo("pre-flight: " + path);
            string kd = Path.Combine(Application.StartupPath, "KeyDiag.exe");
            if (!File.Exists(kd)) { LogErr("KeyDiag.exe is missing next to the GUI"); return; }
            var lines = new List<string>();
            RunProcessCapture(kd, "\"" + path + "\"", Color.Gainsboro, lines);

            string site = null;
            foreach (string ln in lines)
            {
                int i = ln.IndexOf("site RVA = 0x");
                if (i >= 0) site = ln.Substring(i + 12).Trim();
            }
            if (site == null)
                LogWarn("no definitive hook site; pick one from the candidate list above and type its RVA");
            if (site != null) { txtSite.Text = site; LogOk("Site RVA -> " + site); SetStatus("ready"); }
            else SetStatus("no hook site found");
        }
        // ---------------- running ----------------
        int RunProcessCapture(string exe, string args, Color color, List<string> sink)
        {
            var psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
            psi.CreateNoWindow = true; psi.WorkingDirectory = Path.GetDirectoryName(exe);
            var p = new Process(); p.StartInfo = psi;
            p.OutputDataReceived += delegate (object s, DataReceivedEventArgs e)
            {
                if (e.Data == null) return;
                sink.Add(e.Data);
                Append("    " + e.Data, e.Data.StartsWith("  ->") || e.Data.Contains("MATCH") ? Color.LightGreen : color);
            };
            p.ErrorDataReceived += delegate (object s, DataReceivedEventArgs e) { if (e.Data != null) { sink.Add(e.Data); Append("    " + e.Data, Color.IndianRed); } };
            p.Start(); p.BeginOutputReadLine(); p.BeginErrorReadLine(); p.WaitForExit();
            return p.ExitCode;
        }

        int RunProcess(string exe, string args, Color outColor)
        {
            var psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;
            psi.WorkingDirectory = Path.GetDirectoryName(exe);
            var p = new Process();
            p.StartInfo = psi;
            p.OutputDataReceived += delegate (object s, DataReceivedEventArgs e)
            {
                if (e.Data != null) Append("    " + e.Data, e.Data.StartsWith("[-]") ? Color.IndianRed : outColor);
            };
            p.ErrorDataReceived += delegate (object s, DataReceivedEventArgs e)
            {
                if (e.Data != null) Append("    " + e.Data, Color.IndianRed);
            };
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            p.WaitForExit();
            return p.ExitCode;
        }

        static int PeMachine(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read))
                using (var br = new BinaryReader(fs))
                {
                    fs.Position = 0x3C; int lfa = br.ReadInt32();
                    fs.Position = lfa + 4; return br.ReadUInt16();
                }
            }
            catch { return 0; }
        }

        void RunAll(string target, string outDir, string modeSel, string siteRvaText, string pubEText, string holdText)
        {
            try
            {
                string tools = Application.StartupPath;
                bool isExe = target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
                string mode = modeSel;
                if (mode == "Auto")
                {
                    bool is64 = PeMachine(target) == 0x8664;
                    mode = is64 ? "x64" : (isExe ? "EXE" : "DLL");
                    LogInfo("detected: " + (is64 ? "64-bit" : "32-bit") + " image");
                }

                // drop artifacts from previous runs so a stale result cannot look like success
                foreach (string stale in new string[] { "meta.json", "ops.bin", "sig.txt", "target_stdout.txt", "KEY.txt", "private_pkcs1.pem", "private_pkcs8.pem" })
                {
                    try { string sp = Path.Combine(outDir, stale); if (File.Exists(sp)) File.Delete(sp); } catch { }
                }

                SetStatus("collecting...");
                LogInfo("collector mode: " + mode);

                int rc;
                if (mode == "x64")
                {
                    string site64 = siteRvaText;
                    if (site64.StartsWith("0x") || site64.StartsWith("0X")) site64 = site64.Substring(2);
                    if (site64.Length == 0 || site64 == "0")
                    {
                        LogErr("x64 mode needs the hook site RVA (fill in Site RVA)");
                        SetStatus("needs site RVA");
                        return;
                    }
                    LogWarn("x64 tracing is experimental: the logging stub still faults on the test probe");
                    string a64 = "\"" + target + "\" \"" + outDir + "\" " + site64 + " 200000";
                    rc = RunProcess(Path.Combine(tools, "KeyHunterExe64.exe"), a64, Color.LightSteelBlue);
                    if (rc != 0) { LogErr("x64 collector failed (exit " + rc + ")"); SetStatus("failed"); return; }
                    LogWarn("x64 trace captured, but 64-bit limb analysis is not implemented yet");
                    SetStatus("x64 trace only");
                    return;
                }
                if (mode == "EXE")
                {
                    string site = siteRvaText;
                    if (site.StartsWith("0x") || site.StartsWith("0X")) site = site.Substring(2);
                    if (site.Length == 0) site = "0";
                    string args = "\"" + target + "\" \"" + outDir + "\" " + site + " " + pubEText + " " + holdText;
                    rc = RunProcess(Path.Combine(tools, "KeyHunterExe.exe"), args, Color.LightSteelBlue);
                    if (rc != 0)
                    {
                        LogErr("collector failed (exit " + rc + ")");
                        if (rc == 4) LogWarn("hook site not found - run Pre-flight to see the pattern report");
                        SetStatus("failed");
                        return;
                    }
                }
                else
                {
                    // never hardcode the hook RVA: KeyHunter re-derives the limb
                    // site from the fingerprint every run (a different build of the
                    // same source moves it). Pass a site only as a hint.
                    string siteDll = siteRvaText;
                    if (siteDll.StartsWith("0x") || siteDll.StartsWith("0X")) siteDll = siteDll.Substring(2);
                    if (siteDll.Length == 0) siteDll = "0";
                    string args = "\"" + target + "\" \"" + outDir + "\" " + siteDll + " 0 auto";
                    rc = RunProcess(Path.Combine(tools, "KeyHunter.exe"), args, Color.LightSteelBlue);
                    if (rc != 0)
                    {
                        LogErr("collector failed (exit " + rc + ")");
                        if (rc == 3) LogWarn("no export behaved like a signer - is this a signer DLL?");
                        if (rc == 4) LogWarn("limb site / modulus not found - run Pre-flight");
                        if (rc == 5) LogWarn("faulted inside the target - wrong hook site for this build");
                        SetStatus("failed");
                        return;
                    }
                }

                SetStatus("analysing...");
                string py = Path.Combine(tools, "analyze.py");
                int rc2 = RunProcess("python", "\"" + py + "\" \"" + outDir + "\"", Color.Gainsboro);
                if (rc2 != 0) { LogErr("analyzer failed (exit " + rc2 + ")"); SetStatus("failed"); return; }

                string pem = Path.Combine(outDir, "private_pkcs1.pem");
                if (File.Exists(pem))
                {
                    LogOk("private key extracted: " + pem);
                    SetStatus("done");
                }
                else
                {
                    LogWarn("finished but no PEM produced");
                    SetStatus("done (no key)");
                }
            }
            catch (Exception ex)
            {
                LogErr(ex.Message);
                SetStatus("error");
            }
            finally
            {
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        running = false;
                        btnStart.Enabled = btnPreflight.Enabled = true;
                    });
                }
                catch { }
            }
        }

        public void AutoRun(string[] args)
        {
            string target = args[0], outDir = args[1];
            EventHandler h = null;
            h = delegate
            {
                Shown -= h;
                txtTarget.Text = target;
                txtOut.Text = outDir;
                if (args.Length > 2) txtSite.Text = args[2];
                Preflight(target);
                btnStart_Click(null, null);
            };
            Shown += h;
        }

        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            foreach (string a in args) if (a == "--strict") Control.CheckForIllegalCrossThreadCalls = true;
            var f = new MainForm();
            if (args.Length >= 2) f.AutoRun(args);
            Application.Run(f);
        }
    }
}










