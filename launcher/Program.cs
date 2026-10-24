// Crimson Desert Multiplayer launcher. SPDX-License-Identifier: GPL-3.0-only
namespace Cdmp.Launcher;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
