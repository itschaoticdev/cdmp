// Crimson Desert Multiplayer launcher. SPDX-License-Identifier: GPL-3.0-only
using System.Runtime.InteropServices;

namespace Cdmp.Launcher;

/// <summary>Dark steel, bone text, one crimson accent. Square edges, flat, no glow.</summary>
internal static class Theme
{
    public static readonly Color Ground = Color.FromArgb(0x15, 0x15, 0x17);
    public static readonly Color Panel = Color.FromArgb(0x1F, 0x1F, 0x22);
    public static readonly Color Field = Color.FromArgb(0x0F, 0x0F, 0x11);
    public static readonly Color Line = Color.FromArgb(0x3A, 0x3A, 0x3F);
    public static readonly Color Ink = Color.FromArgb(0xE6, 0xE1, 0xD8);
    public static readonly Color Muted = Color.FromArgb(0x9A, 0x95, 0x8C);
    public static readonly Color Faint = Color.FromArgb(0x66, 0x63, 0x5E);
    public static readonly Color Accent = Color.FromArgb(0x9B, 0x1B, 0x1F);
    public static readonly Color AccentHover = Color.FromArgb(0xB5, 0x24, 0x28);
    public static readonly Color Good = Color.FromArgb(0x7F, 0xA8, 0x6A);
    public static readonly Color Bad = Color.FromArgb(0xD0, 0x5A, 0x4E);

    public static readonly Font Body = new("Segoe UI", 9.5f);
    public static readonly Font Small = new("Segoe UI", 8f);
    public static readonly Font Label = new("Segoe UI Semibold", 9f);
    public static readonly Font Title = new("Georgia", 18f, FontStyle.Bold);
    public static readonly Font Code = new("Consolas", 16f, FontStyle.Bold);

    /// <summary>Colours every control in the tree that has no look of its own.</summary>
    public static void Apply(Control root)
    {
        foreach (Control c in root.Controls)
        {
            switch (c)
            {
                case Button b: Flat(b, b.Tag as string == "primary"); break;
                case TextBox t:
                    t.BackColor = Field; t.ForeColor = Ink; t.BorderStyle = BorderStyle.FixedSingle;
                    if (t.Font == Control.DefaultFont) t.Font = Body;
                    break;
                case RadioButton or CheckBox: c.ForeColor = Ink; c.Font = Body; break;
            }
            if (c.HasChildren) Apply(c);
        }
    }

    public static void Flat(Button b, bool primary)
    {
        b.FlatStyle = FlatStyle.Flat;
        b.FlatAppearance.BorderSize = 1;
        b.Font = Label;
        b.Cursor = Cursors.Hand;
        void Paint()
        {
            if (!b.Enabled) { b.BackColor = Panel; b.ForeColor = Faint; b.FlatAppearance.BorderColor = Line; return; }
            b.BackColor = primary ? Accent : Panel;
            b.ForeColor = Ink;
            b.FlatAppearance.BorderColor = primary ? Accent : Muted;
            b.FlatAppearance.MouseOverBackColor = primary ? AccentHover : Line;
            b.FlatAppearance.MouseDownBackColor = primary ? Accent : Field;
        }
        b.EnabledChanged += (_, _) => Paint();
        Paint();
    }

    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    /// <summary>A dark title bar on Windows 10 1809+ and 11 (ignored elsewhere).</summary>
    public static void DarkTitleBar(Form f)
    {
        try { int on = 1; if (DwmSetWindowAttribute(f.Handle, 20, ref on, 4) != 0) DwmSetWindowAttribute(f.Handle, 19, ref on, 4); }
        catch { }
    }
}
