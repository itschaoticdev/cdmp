// Crimson Desert Multiplayer launcher. SPDX-License-Identifier: GPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace Cdmp.Launcher;

/// <summary>Finds Crimson Desert and installs or removes the mod in its bin64 folder.</summary>
internal static class Game
{
    public const string SteamAppId = "3321460";
    public const string Exe = "CrimsonDesert.exe";

    /// <summary>The bin64 folder of the Steam install, or null.</summary>
    public static string? Find()
    {
        foreach (var lib in SteamLibraries())
        {
            var manifest = Path.Combine(lib, "steamapps", $"appmanifest_{SteamAppId}.acf");
            if (!File.Exists(manifest)) continue;
            var m = Regex.Match(File.ReadAllText(manifest), "\"installdir\"\\s+\"([^\"]+)\"");
            if (!m.Success) continue;
            var dir = Path.Combine(lib, "steamapps", "common", m.Groups[1].Value);
            var bin = BinFolder(dir);
            if (bin != null) return bin;
        }
        return null;
    }

    /// <summary>The folder with CrimsonDesert.exe, given it or the game's root folder.</summary>
    public static string? BinFolder(string dir)
    {
        if (File.Exists(Path.Combine(dir, Exe))) return dir;
        var bin = Path.Combine(dir, "bin64");
        return File.Exists(Path.Combine(bin, Exe)) ? bin : null;
    }

    private static IEnumerable<string> SteamLibraries()
    {
        var steam = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string
                    ?? Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath", null) as string;
        if (steam == null) yield break;
        steam = steam.Replace('/', '\\');
        yield return steam;
        var vdf = Path.Combine(steam, "steamapps", "libraryfolders.vdf");
        if (!File.Exists(vdf)) yield break;
        foreach (Match m in Regex.Matches(File.ReadAllText(vdf), "\"path\"\\s+\"([^\"]+)\""))
            yield return m.Groups[1].Value.Replace(@"\\", @"\");
    }

    // The only game build the mod's offsets are for: kPeTimestamp in src/mod/game/offsets.h
    // (launcher.tests checks the two agree). Any other build and the mod switches its game
    // readers off, so co-op silently does nothing - better to say so before launching.
    public const uint SupportedPeTimestamp = 0x6AB28F00;
    public const string SupportedBuild = "1.0.0.2976";
    public const string BuildProblemPrefix = "Your Crimson Desert is version ";

    /// <summary>The PE header TimeDateStamp of the exe, or null if it isn't a readable PE file.</summary>
    public static uint? PeTimestamp(string exe)
    {
        try
        {
            using var r = new BinaryReader(File.OpenRead(exe));
            if (r.BaseStream.Length < 0x40 || r.ReadUInt16() != 0x5A4D) return null; // "MZ"
            r.BaseStream.Position = 0x3C;
            long nt = r.ReadUInt32();
            if (nt + 12 > r.BaseStream.Length) return null;
            r.BaseStream.Position = nt;
            if (r.ReadUInt32() != 0x00004550) return null; // "PE\0\0"
            r.BaseStream.Position = nt + 8;
            return r.ReadUInt32();
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    /// <summary>Null when the game in bin is the build the mod supports, else what to tell the player.</summary>
    public static string? BuildProblem(string bin)
    {
        var exe = Path.Combine(bin, Exe);
        var ts = PeTimestamp(exe);
        if (ts == SupportedPeTimestamp) return null;
        // A patch can keep the file version and still move every offset, so the stamp is always shown.
        var ver = FileVersionInfo.GetVersionInfo(exe).FileVersion?.Trim();
        var stamp = ts is { } t ? $"build stamp 0x{t:X8}" : "unreadable exe";
        var which = string.IsNullOrEmpty(ver) ? stamp : $"{ver} ({stamp})";
        return $"{BuildProblemPrefix}{which}. This mod only works with {SupportedBuild} so far, " +
               "so co-op would stay off in game. Watch the mod page for an update.";
    }

    public static bool Running() => Process.GetProcessesByName("CrimsonDesert").Length > 0;

    public static void Launch() =>
        Process.Start(new ProcessStartInfo($"steam://rungameid/{SteamAppId}") { UseShellExecute = true });
}

internal enum ModState { NotInstalled, Installed, Outdated, ForeignLoader }

/// <summary>The files the launcher carries (cdmp.asi and the ASI loader) and puts in bin64.</summary>
internal static class Mod
{
    private const string AsiName = "cdmp.asi";
    // The game imports WINMM.dll, so Ultimate ASI Loader goes in as winmm.dll.
    private const string LoaderName = "winmm.dll";

    public static byte[] Payload(string name)
    {
        using var s = typeof(Mod).Assembly.GetManifestResourceStream(name)
                      ?? throw new InvalidOperationException($"missing resource {name}");
        using var m = new MemoryStream();
        s.CopyTo(m);
        return m.ToArray();
    }

    public static string Template(bool host) =>
        System.Text.Encoding.UTF8.GetString(Payload(host ? "template.host.ini" : "template.guest.ini"));

    public static ModState State(string bin)
    {
        var loader = Path.Combine(bin, LoaderName);
        if (File.Exists(loader) && !SameBytes(loader, Payload("payload.winmm.dll"))) return ModState.ForeignLoader;
        var asi = Path.Combine(bin, AsiName);
        if (!File.Exists(asi) || !File.Exists(loader)) return ModState.NotInstalled;
        return SameBytes(asi, Payload("payload.cdmp.asi")) ? ModState.Installed : ModState.Outdated;
    }

    public static void Install(string bin)
    {
        if (Game.Running()) throw new InvalidOperationException("Close Crimson Desert first (its files are locked while it runs).");
        if (State(bin) == ModState.ForeignLoader)
            throw new InvalidOperationException("Another mod's winmm.dll is in the game folder. Remove it first, or install the mod by hand.");
        File.WriteAllBytes(Path.Combine(bin, AsiName), Payload("payload.cdmp.asi"));
        var loader = Path.Combine(bin, LoaderName);
        if (!File.Exists(loader)) File.WriteAllBytes(loader, Payload("payload.winmm.dll"));
    }

    /// <summary>Removes what we installed. cdmp.ini and the logs stay.</summary>
    public static void Remove(string bin)
    {
        if (Game.Running()) throw new InvalidOperationException("Close Crimson Desert first (its files are locked while it runs).");
        var asi = Path.Combine(bin, AsiName);
        if (File.Exists(asi)) File.Delete(asi);
        var loader = Path.Combine(bin, LoaderName);
        // Only our loader: never someone else's winmm.dll.
        if (File.Exists(loader) && SameBytes(loader, Payload("payload.winmm.dll"))) File.Delete(loader);
    }

    private static bool SameBytes(string path, byte[] data)
    {
        var info = new FileInfo(path);
        if (info.Length != data.Length) return false;
        return SHA256.HashData(File.ReadAllBytes(path)).AsSpan().SequenceEqual(SHA256.HashData(data));
    }
}
