// Crimson Desert Multiplayer launcher. SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;

namespace Cdmp.Launcher;

public sealed class MainForm : Form
{
    public const string SiteUrl = "https://cdmp.breakneckhosting.com";

    private readonly Settings _s = Settings.Load();
    private readonly Label _gamePath = new() { AutoSize = true, ForeColor = Theme.Ink, Font = Theme.Body, MaximumSize = new Size(380, 0) };
    private readonly Label _modState = new() { AutoSize = true, Font = Theme.Body };
    private readonly Button _browse = new() { Text = "Change...", Width = 90, Height = 28 };
    private readonly Button _install = new() { Text = "Install", Width = 90, Height = 28 };
    private readonly TextBox _name = new() { Width = 260 };
    private readonly RadioButton _hostMode = new() { Text = "Host a game", AutoSize = true };
    private readonly RadioButton _joinMode = new() { Text = "Join a friend", AutoSize = true };
    private readonly Label _hostCode = new() { AutoSize = true, Font = Theme.Code, ForeColor = Theme.Ink };
    private readonly Button _copy = new() { Text = "Copy", Width = 80, Height = 28 };
    private readonly Button _newCode = new() { Text = "New code", Width = 90, Height = 28 };
    private readonly TextBox _joinCode = new() { Width = 300, Font = new Font("Consolas", 14f), CharacterCasing = CharacterCasing.Upper };
    private readonly Label _hint = new() { AutoSize = true, ForeColor = Theme.Muted, Font = Theme.Small, MaximumSize = new Size(490, 0) };
    private readonly Button _play = new() { Text = "Start Crimson Desert", Tag = "primary", Height = 40, Dock = DockStyle.Fill };
    private readonly Label _status = new() { AutoSize = true, ForeColor = Theme.Muted, Font = Theme.Small, MaximumSize = new Size(470, 0) };
    private readonly FlowLayoutPanel _hostPanel = new() { AutoSize = true, WrapContents = false, Margin = new Padding(0, 4, 0, 2) };
    private readonly FlowLayoutPanel _joinPanel = new() { AutoSize = true, WrapContents = false, Margin = new Padding(0, 4, 0, 2) };

    public MainForm()
    {
        Text = "Crimson Desert Multiplayer";
        BackColor = Theme.Ground;
        ForeColor = Theme.Ink;
        Font = Theme.Body;
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(540, 580);
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(22, 18, 22, 14), AutoScroll = true };
        Controls.Add(root);

        var title = new Label { Text = "Crimson Desert Multiplayer", Font = Theme.Title, ForeColor = Theme.Ink, AutoSize = true };
        var sub = new Label { Text = $"Unofficial co-op mod, alpha {typeof(MainForm).Assembly.GetName().Version?.ToString(3)}", ForeColor = Theme.Muted, AutoSize = true, Margin = new Padding(3, 0, 3, 14) };
        root.Controls.Add(title);
        root.Controls.Add(sub);

        root.Controls.Add(Section("Game"));
        var gameRow = Row(_gamePath);
        root.Controls.Add(gameRow);
        root.Controls.Add(Row(_modState));
        root.Controls.Add(Row(_browse, _install));

        root.Controls.Add(Section("Your name"));
        root.Controls.Add(Row(_name));

        root.Controls.Add(Section("Play"));
        root.Controls.Add(Row(_hostMode, _joinMode));

        _hostPanel.Controls.AddRange([_hostCode, _copy, _newCode]);
        _hostCode.Margin = new Padding(3, 0, 6, 0);
        _copy.Margin = _newCode.Margin = new Padding(6, 4, 0, 0);
        _joinPanel.Controls.Add(_joinCode);
        root.Controls.Add(_hostPanel);
        root.Controls.Add(_joinPanel);
        root.Controls.Add(_hint);

        var playHolder = new Panel { Height = 40, Dock = DockStyle.Top, Margin = new Padding(3, 16, 3, 6) };
        playHolder.Controls.Add(_play);
        root.Controls.Add(playHolder);
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        playHolder.Width = 490;
        root.Controls.Add(_status);

        var footer = new LinkLabel
        {
            Text = "Not affiliated with Pearl Abyss. Free and open source (GPL-3.0). Guide and source",
            AutoSize = true, Font = Theme.Small, LinkColor = Theme.Muted, ActiveLinkColor = Theme.Ink, ForeColor = Theme.Faint,
            Margin = new Padding(3, 12, 3, 0), MaximumSize = new Size(470, 0),
        };
        footer.LinkArea = new LinkArea(footer.Text.IndexOf("Guide", StringComparison.Ordinal), "Guide and source".Length);
        footer.LinkClicked += (_, _) => Open(SiteUrl);
        root.Controls.Add(footer);

        Theme.Apply(this);
        _hostCode.Font = Theme.Code;

        _name.Text = _s.Name;
        _joinCode.Text = _s.JoinCode is { } j ? RoomCode.Format(j) : "";
        _s.HostCode ??= RoomCode.New();
        _hostMode.Checked = _s.Host;
        _joinMode.Checked = !_s.Host;

        _browse.Click += (_, _) => PickGame();
        _install.Click += (_, _) => ToggleInstall();
        _hostMode.CheckedChanged += (_, _) => ShowMode();
        _copy.Click += (_, _) => { Clipboard.SetText(RoomCode.Format(_s.HostCode!)); Status("Code copied. Send it to your friend."); };
        _newCode.Click += (_, _) => { _s.HostCode = RoomCode.New(); ShowMode(); _s.Save(); };
        _joinCode.TextChanged += (_, _) => ShowMode();
        _play.Click += (_, _) => Play();
        FormClosing += (_, _) => { _s.Name = _name.Text; _s.JoinCode = RoomCode.Normalize(_joinCode.Text) ?? _s.JoinCode; _s.Save(); };
        HandleCreated += (_, _) => Theme.DarkTitleBar(this);

        if (_s.GameDir == null || Game.BinFolder(_s.GameDir) == null) _s.GameDir = Game.Find();
        RefreshGame();
        ShowMode();
    }

    private static Label Section(string text) => new()
    {
        Text = text, Font = Theme.Label, ForeColor = Theme.Muted, AutoSize = true, Margin = new Padding(3, 12, 3, 4),
    };

    private static FlowLayoutPanel Row(params Control[] items)
    {
        var f = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Margin = new Padding(0, 2, 0, 2) };
        foreach (var c in items) { c.Margin = new Padding(3, 3, 12, 3); f.Controls.Add(c); }
        return f;
    }

    private string? Bin => _s.GameDir is { } d ? Game.BinFolder(d) : null;

    private void RefreshGame()
    {
        var bin = Bin;
        if (bin == null)
        {
            _gamePath.Text = "Crimson Desert not found. Click Change... and pick its folder.";
            _modState.Text = "";
            _install.Enabled = false;
            _play.Enabled = false;
            return;
        }
        _gamePath.Text = bin;
        _install.Enabled = true;
        _play.Enabled = true;
        var problem = Game.BuildProblem(bin);
        if (problem != null) Status(problem, bad: true);
        else if (_status.Text.StartsWith(Game.BuildProblemPrefix)) Status(""); // a supported folder was picked after an old one
        switch (Mod.State(bin))
        {
            case ModState.Installed: _modState.Text = "Mod installed"; _modState.ForeColor = Theme.Good; _install.Text = "Remove"; break;
            case ModState.Outdated: _modState.Text = "Mod installed (older version, Start will update it)"; _modState.ForeColor = Theme.Muted; _install.Text = "Remove"; break;
            case ModState.ForeignLoader: _modState.Text = "Another mod's winmm.dll is in the game folder"; _modState.ForeColor = Theme.Bad; _install.Text = "Install"; break;
            default: _modState.Text = "Mod not installed (Start installs it)"; _modState.ForeColor = Theme.Muted; _install.Text = "Install"; break;
        }
    }

    private void ShowMode()
    {
        bool host = _hostMode.Checked;
        _s.Host = host;
        _hostPanel.Visible = host;
        _joinPanel.Visible = !host;
        _hostCode.Text = RoomCode.Format(_s.HostCode!);
        if (host)
        {
            _hint.Text = "Send this code to your friend, then press Start. Anyone with the code can join, so only share it with them.";
        }
        else
        {
            var code = RoomCode.Normalize(_joinCode.Text);
            _hint.Text = _joinCode.Text.Trim().Length == 0 ? "Paste the code your friend sent you."
                       : code == null ? "That doesn't look like a code yet (16 letters and numbers)."
                       : "Code OK. Your friend has to start their game first.";
        }
    }

    private void PickGame()
    {
        using var dlg = new FolderBrowserDialog { Description = "Pick the Crimson Desert folder", UseDescriptionForTitle = true };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        if (Game.BinFolder(dlg.SelectedPath) == null)
        {
            Status($"No {Game.Exe} in that folder or its bin64 folder.", bad: true);
            return;
        }
        _s.GameDir = dlg.SelectedPath;
        _s.Save();
        RefreshGame();
    }

    private void ToggleInstall()
    {
        var bin = Bin;
        if (bin == null) return;
        try
        {
            if (Mod.State(bin) is ModState.Installed or ModState.Outdated) { Mod.Remove(bin); Status("Mod removed. Your cdmp.ini and logs were kept."); }
            else { Mod.Install(bin); Status("Mod installed."); }
        }
        catch (Exception e) { Status(e.Message, bad: true); }
        RefreshGame();
    }

    private void Play()
    {
        var bin = Bin;
        if (bin == null) return;
        bool host = _hostMode.Checked;
        string? code = host ? _s.HostCode : RoomCode.Normalize(_joinCode.Text);
        if (code == null) { Status("Enter your friend's code first.", bad: true); return; }
        if (Game.BuildProblem(bin) is { } problem) { Status(problem, bad: true); return; }
        try
        {
            if (Mod.State(bin) != ModState.Installed) Mod.Install(bin);
            var ini = Path.Combine(bin, "cdmp.ini");
            if (File.Exists(ini) && !File.Exists(ini + ".before-launcher")) File.Copy(ini, ini + ".before-launcher");
            File.WriteAllText(ini, Ini.Build(host, _name.Text, _s.Relay, code), new System.Text.UTF8Encoding(false));
            _s.Name = _name.Text;
            if (!host) _s.JoinCode = code;
            _s.Save();
            Game.Launch();
            Status(host ? "Starting the game. Your friend can join once you're in the world."
                        : "Starting the game. You'll meet your friend once you're both in the world.");
        }
        catch (Exception e) { Status(e.Message, bad: true); }
        RefreshGame();
    }

    private void Status(string text, bool bad = false)
    {
        _status.Text = text;
        _status.ForeColor = bad ? Theme.Bad : Theme.Muted;
    }

    private static void Open(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
    }
}
