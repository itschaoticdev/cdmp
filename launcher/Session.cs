// Crimson Desert Multiplayer launcher. SPDX-License-Identifier: GPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cdmp.Launcher;

/// <summary>Room codes in the mod's format (src/common/room_code.cpp): 16 Crockford base32 characters.</summary>
internal static class RoomCode
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public static string New()
    {
        var sb = new StringBuilder(16);
        for (int i = 0; i < 16; i++) sb.Append(Alphabet[RandomNumberGenerator.GetInt32(32)]);
        return sb.ToString();
    }

    /// <summary>The canonical code from what someone typed or pasted, or null. Same rules as the mod.</summary>
    public static string? Normalize(string? text)
    {
        if (text == null) return null;
        var sb = new StringBuilder(16);
        foreach (var raw in text)
        {
            if (raw is '-' or ' ' or '\t') continue;
            var c = char.ToUpperInvariant(raw);
            c = c switch { 'O' => '0', 'I' or 'L' => '1', _ => c };
            if (Alphabet.IndexOf(c) < 0) return null;
            sb.Append(c);
        }
        return sb.Length == 16 ? sb.ToString() : null;
    }

    public static string Format(string code) =>
        string.Join("-", Enumerable.Range(0, code.Length / 4).Select(i => code.Substring(i * 4, 4)));
}

/// <summary>Edits cdmp.ini keys in place, keeping the comments of the template.</summary>
internal static class Ini
{
    public static string Set(string text, string section, string key, string value)
    {
        var lines = text.Replace("\r\n", "\n").Split('\n').ToList();
        int start = lines.FindIndex(l => l.Trim().Equals($"[{section}]", StringComparison.OrdinalIgnoreCase));
        if (start < 0)
        {
            if (lines.Count > 0 && lines[^1].Length != 0) lines.Add("");
            lines.Add($"[{section}]");
            lines.Add($"{key}={value}");
            return string.Join("\r\n", lines);
        }
        int end = lines.FindIndex(start + 1, l => l.TrimStart().StartsWith('['));
        if (end < 0) end = lines.Count;
        for (int i = start + 1; i < end; i++)
        {
            var t = lines[i].TrimStart();
            if (t.StartsWith(';')) continue;
            int eq = t.IndexOf('=');
            if (eq > 0 && t[..eq].Trim().Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                lines[i] = $"{key}={value}";
                return string.Join("\r\n", lines);
            }
        }
        // Not there: right after the last non-empty line of the section.
        int at = end;
        while (at > start + 1 && lines[at - 1].Trim().Length == 0) at--;
        lines.Insert(at, $"{key}={value}");
        return string.Join("\r\n", lines);
    }

    /// <summary>Only what the mod reads in a name: printable ASCII, no '=' or newlines, 24 characters.</summary>
    public static string CleanName(string name)
    {
        var s = new string(name.Where(c => c >= 0x20 && c < 0x7F && c != '=' && c != ';').ToArray()).Trim();
        if (s.Length > 24) s = s[..24];
        return s.Length == 0 ? "Player" : s;
    }

    /// <summary>The full cdmp.ini for a host or a guest joining through the relay.</summary>
    public static string Build(bool host, string name, string relay, string code)
    {
        var text = Mod.Template(host);
        text = Set(text, "general", "player_name", CleanName(name));
        text = Set(text, "net", "transport", "relay");
        text = Set(text, "net", "role", host ? "host" : "guest");
        text = Set(text, "relay", "server", relay);
        text = Set(text, "relay", "room", RoomCode.Format(code));
        return text;
    }
}

/// <summary>What the launcher remembers, in %APPDATA%\CDMP\launcher.json.</summary>
internal sealed class Settings
{
    // Breakneck's relay (tools/relay, cdmp_relay.exe).
    public const string DefaultRelay = "66.51.99.113:37020";

    public string Name { get; set; } = Environment.UserName;
    public string? GameDir { get; set; }
    public string? HostCode { get; set; }
    public string? JoinCode { get; set; }
    public bool Host { get; set; } = true;
    public string Relay { get; set; } = DefaultRelay;

    private static string PathOf() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CDMP", "launcher.json");

    public static Settings Load()
    {
        try { return JsonSerializer.Deserialize<Settings>(File.ReadAllText(PathOf())) ?? new Settings(); }
        catch { return new Settings(); }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PathOf())!);
            File.WriteAllText(PathOf(), JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { }
    }
}
