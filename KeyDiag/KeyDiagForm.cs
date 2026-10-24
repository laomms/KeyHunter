using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

// Desktop front-end for KeyDiag. The console path is still available:
//   KeyDiag.exe <target>   -> prints the report to stdout
//   KeyDiag.exe            -> opens this window
public class KeyDiagForm : Form
{
    TextBox txtTarget;
    RichTextBox rtb;
    ToolStripStatusLabel lbl;

    public KeyDiagForm()
    {
        Text = "KeyDiag - PE pre-flight";
        Width = 900; Height = 620;
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Consolas", 9f);

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 44, Padding = new Padding(8, 10, 8, 0), WrapContents = false };
        top.Controls.Add(new Label { Text = "Target:", AutoSize = true, Padding = new Padding(0, 5, 6, 0) });
        txtTarget = new TextBox { Width = 560 };
        top.Controls.Add(txtTarget);
        var btnBrowse = new Button { Text = "Browse...", Width = 80 };
        btnBrowse.Click += delegate
        {
            var d = new OpenFileDialog();
            d.Filter = "PE files (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*";
            if (d.ShowDialog() == DialogResult.OK) { txtTarget.Text = d.FileName; Analyze(); }
        };
        top.Controls.Add(btnBrowse);
        var btnRun = new Button { Text = "Analyze", Width = 80 };
        btnRun.Click += delegate { Analyze(); };
        top.Controls.Add(btnRun);
        var btnCopy = new Button { Text = "Copy", Width = 70 };
        btnCopy.Click += delegate { if (rtb.TextLength > 0) Clipboard.SetText(rtb.Text); };
        top.Controls.Add(btnCopy);

        rtb = new RichTextBox();
        rtb.Dock = DockStyle.Fill;
        rtb.ReadOnly = true;
        rtb.BackColor = Color.FromArgb(30, 30, 30);
        rtb.ForeColor = Color.Gainsboro;
        rtb.Font = new Font("Consolas", 9f);
        rtb.WordWrap = false;

        var status = new StatusStrip();
        lbl = new ToolStripStatusLabel("pick a target to inspect");
        status.Items.Add(lbl);

        Controls.Add(rtb);
        Controls.Add(top);
        Controls.Add(status);

        Append("KeyDiag ready. Pick an .exe/.dll and press Analyze.", Color.Gainsboro);
        Append("", Color.Gainsboro);
        Append("What it reports:", Color.Gray);
        Append("  machine / subsystem / entry / sections / imports", Color.Gray);
        Append("  signer fingerprint  - 84 fixed bytes, unique to the SignPKCS asm build", Color.Gray);
        Append("  limb-site fingerprint - 20 fixed bytes around the limb-multiply call", Color.Gray);
        Append("  candidate hook sites  - calls into small functions containing MUL", Color.Gray);
    }

    void Append(string s, Color c)
    {
        rtb.SelectionStart = rtb.TextLength;
        rtb.SelectionLength = 0;
        rtb.SelectionColor = c;
        rtb.AppendText(s + Environment.NewLine);
        rtb.SelectionColor = rtb.ForeColor;
        rtb.ScrollToCaret();
    }

    static Color ColorFor(string line)
    {
        if (line.Contains("MATCH")) return Color.LightGreen;
        if (line.Contains("NOT FOUND") || line.Contains("not the same")) return Color.Orange;
        if (line.Contains("candidate hook sites")) return Color.LightSkyBlue;
        if (line.TrimStart().StartsWith("0x")) return Color.LightSteelBlue;
        if (line.Contains("->")) return Color.LightGreen;
        return Color.Gainsboro;
    }

    void Analyze()
    {
        string path = txtTarget.Text.Trim();
        if (path.Length == 0) { lbl.Text = "no target"; return; }
        if (!File.Exists(path)) { Append("[-] not found: " + path, Color.IndianRed); lbl.Text = "not found"; return; }
        try
        {
            var lines = KeyDiag.BuildReport(path);
            rtb.Clear();
            foreach (string l in lines) Append(l, ColorFor(l));
            lbl.Text = "analyzed " + Path.GetFileName(path);
        }
        catch (Exception ex)
        {
            Append("[-] " + ex.Message, Color.IndianRed);
            lbl.Text = "error";
        }
    }
}
