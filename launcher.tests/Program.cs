// Checks for the launcher's logic. No framework: each failure prints and the exit code is non-zero.
using Cdmp.Launcher;

if (args.Length == 2 && args[0] == "--shot")
{
    // Renders the window off-screen to a PNG (looking at the layout without opening it on a shared desktop).
    ApplicationConfiguration.Initialize();
    using var f = new MainForm { StartPosition = FormStartPosition.Manual, Location = new Point(-4000, -4000), ShowInTaskbar = false };
    f.Show();
    Application.DoEvents();
    using var bmp = new Bitmap(f.ClientSize.Width, f.ClientSize.Height);
    f.DrawToBitmap(bmp, new Rectangle(Point.Empty, f.ClientSize));
    bmp.Save(args[1]);
    return 0;
}

int failures = 0;
void Check(bool ok, string what)
{
    if (ok) return;
    Console.WriteLine($"FAIL {what}");
    failures++;
}

// Room codes: the mod's format and the mod's typing rules (tests/relay_tests.inc).
var a = RoomCode.New();
var b = RoomCode.New();
Check(a.Length == 16 && a != b, "new codes are 16 chars and differ");
Check(a.All(c => "0123456789ABCDEFGHJKMNPQRSTVWXYZ".Contains(c)), "new code uses the Crockford alphabet");
Check(RoomCode.Format("01ABCDEFGHJKMNPQ") == "01AB-CDEF-GHJK-MNPQ", "format");
Check(RoomCode.Normalize("o1ab cdef-ghjk mnpq") == "01ABCDEFGHJKMNPQ", "normalize like the mod");
Check(RoomCode.Normalize("0IAB-CDEF-GHJK-MNPL") == "01ABCDEFGHJKMNP1", "I/L are 1");
Check(RoomCode.Normalize("ABCD-EFGH-JKMN") == null, "too short");
Check(RoomCode.Normalize("ABCD-EFGH-JKMN-PQRU") == null, "U is not a digit");
Check(RoomCode.Normalize(RoomCode.Format(a)) == a, "round trip");

// Ini edits keep comments and touch only the key in its section.
const string sample = "; top\r\n[net]\r\n; transport comment\r\ntransport=steam\r\nrole=host\r\n\r\n[steam]\r\npeer_steamid=\r\n";
var edited = Ini.Set(sample, "net", "transport", "relay");
Check(edited.Contains("transport=relay") && !edited.Contains("transport=steam") && edited.Contains("; transport comment"), "set existing key");
var added = Ini.Set(sample, "net", "send_rate_hz", "20");
Check(added.IndexOf("send_rate_hz=20") < added.IndexOf("[steam]"), "new key stays in its section");
var newSection = Ini.Set(sample, "relay", "room", "X");
Check(newSection.TrimEnd().EndsWith("[relay]\r\nroom=X"), "new section at the end");
Check(Ini.Set("[a]\r\n;x=1\r\n", "a", "x", "2").Contains("x=2") && Ini.Set("[a]\r\n;x=1\r\n", "a", "x", "2").Contains(";x=1"), "commented key is not edited");
Check(Ini.CleanName("Bad=Name;\nwith\ttabs and a very long tail that goes on") == "BadNamewithtabs and a ve", "name cleaned and cut to 24");
Check(Ini.CleanName("   ") == "Player", "empty name");

// The full ini from the real templates.
var host = Ini.Build(true, "Kody", "1.2.3.4:37020", "01ABCDEFGHJKMNPQ");
var guest = Ini.Build(false, "Friend", "1.2.3.4:37020", "01ABCDEFGHJKMNPQ");
foreach (var (ini, role) in new[] { (host, "host"), (guest, "guest") })
{
    Check(ini.Contains("transport=relay") && !ini.Contains("transport=steam"), $"{role}: relay transport");
    Check(ini.Contains($"role={role}"), $"{role}: role");
    Check(ini.Contains("[relay]") && ini.Contains("server=1.2.3.4:37020") && ini.Contains("room=01AB-CDEF-GHJK-MNPQ"), $"{role}: relay section");
    Check(ini.Contains("[coop]") && ini.Contains("enabled=1"), $"{role}: template kept");
}
Check(host.Contains("player_name=Kody") && host.Contains("enemy_relay=1"), "host template");
Check(guest.Contains("player_name=Friend") && guest.Contains("enemy_relay=0") && guest.Contains("time_sync=2"), "guest template");

// Install / remove in a stand-in game folder.
var dir = Path.Combine(Path.GetTempPath(), "cdmp_launcher_test_" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(Path.Combine(dir, "bin64"));
File.WriteAllText(Path.Combine(dir, "bin64", Game.Exe), "stand-in");
var bin = Game.BinFolder(dir)!;
Check(bin.EndsWith("bin64"), "bin64 found from the game root");
Check(Mod.State(bin) == ModState.NotInstalled, "starts not installed");
Mod.Install(bin);
Check(Mod.State(bin) == ModState.Installed, "installed");
Check(File.ReadAllBytes(Path.Combine(bin, "cdmp.asi")).SequenceEqual(Mod.Payload("payload.cdmp.asi")), "asi is the payload");
File.WriteAllText(Path.Combine(bin, "cdmp.asi"), "old build");
Check(Mod.State(bin) == ModState.Outdated, "older asi is outdated");
Mod.Install(bin);
Check(Mod.State(bin) == ModState.Installed, "update");
File.WriteAllText(Path.Combine(bin, "cdmp.ini"), "keep me");
Mod.Remove(bin);
Check(!File.Exists(Path.Combine(bin, "cdmp.asi")) && !File.Exists(Path.Combine(bin, "winmm.dll")), "removed");
Check(File.ReadAllText(Path.Combine(bin, "cdmp.ini")) == "keep me", "ini kept on remove");
// Someone else's winmm.dll: never overwritten or deleted.
File.WriteAllText(Path.Combine(bin, "winmm.dll"), "another mod");
Check(Mod.State(bin) == ModState.ForeignLoader, "foreign loader detected");
bool threw = false;
try { Mod.Install(bin); } catch (InvalidOperationException) { threw = true; }
Check(threw && File.ReadAllText(Path.Combine(bin, "winmm.dll")) == "another mod", "foreign loader left alone on install");
Mod.Remove(bin);
Check(File.ReadAllText(Path.Combine(bin, "winmm.dll")) == "another mod", "foreign loader left alone on remove");
Directory.Delete(dir, true);

// The embedded asi is the signed one.
var payloadPath = Path.Combine(Path.GetTempPath(), "cdmp_payload_check.asi");
File.WriteAllBytes(payloadPath, Mod.Payload("payload.cdmp.asi"));
var signed = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(payloadPath);
Check(signed.Subject.Contains("Kodian Anderson"), "payload asi carries the signature");
File.Delete(payloadPath);

// Game build check: reads the PE TimeDateStamp of CrimsonDesert.exe.
static byte[] FakePe(uint timestamp)
{
    var b = new byte[0x200];
    b[0] = (byte)'M'; b[1] = (byte)'Z';
    BitConverter.GetBytes(0x80u).CopyTo(b, 0x3C);
    b[0x80] = (byte)'P'; b[0x81] = (byte)'E';
    BitConverter.GetBytes(timestamp).CopyTo(b, 0x88);
    return b;
}
var gdir = Path.Combine(Path.GetTempPath(), "cdmp_build_test_" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(gdir);
var gexe = Path.Combine(gdir, Game.Exe);
File.WriteAllBytes(gexe, FakePe(Game.SupportedPeTimestamp));
Check(Game.PeTimestamp(gexe) == Game.SupportedPeTimestamp, "reads the PE timestamp");
Check(Game.BuildProblem(gdir) == null, "supported build has no problem");
File.WriteAllBytes(gexe, FakePe(0x6B000000));
var problem = Game.BuildProblem(gdir);
Check(problem != null && problem.StartsWith(Game.BuildProblemPrefix) && problem.Contains("0x6B000000") && problem.Contains(Game.SupportedBuild),
      "other build is reported with its stamp and the supported version");
File.WriteAllText(gexe, "stand-in");
Check(Game.PeTimestamp(gexe) == null && Game.BuildProblem(gdir) != null, "a non-PE exe is not taken as supported");
var truncated = FakePe(Game.SupportedPeTimestamp);
BitConverter.GetBytes(0x7FFFFFF0u).CopyTo(truncated, 0x3C);
File.WriteAllBytes(gexe, truncated);
Check(Game.PeTimestamp(gexe) == null, "e_lfanew past the end is rejected");
Directory.Delete(gdir, true);

// The launcher's supported build must be the one the mod's offsets are for.
string? offsets = null;
for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null && offsets == null; d = d.Parent)
    if (File.Exists(Path.Combine(d.FullName, "src", "mod", "game", "offsets.h"))) offsets = Path.Combine(d.FullName, "src", "mod", "game", "offsets.h");
if (offsets != null)
    Check(File.ReadAllText(offsets).Contains($"kPeTimestamp = 0x{Game.SupportedPeTimestamp:X8};"), "launcher build matches offsets.h kPeTimestamp");
else
    Check(false, "offsets.h found from " + AppContext.BaseDirectory);

Console.WriteLine(failures == 0 ? "All launcher tests passed" : $"{failures} failed");
return failures == 0 ? 0 : 1;
