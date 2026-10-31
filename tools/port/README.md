# Porting offsets to a new game build

`cd_port.py OLD.exe NEW.exe [src/mod/game/offsets.h] [--json report.json]` carries the
RVAs in `offsets.h` from the build they were verified on to a new `CrimsonDesert.exe`,
offline:

- functions (anything with a `...Head[]` array, plus `kClientClock`): the masked prologue,
  grown until it is unique in the new exe. New `Head[]` bytes are printed too.
- globals: every RIP-relative reference in the old exe becomes a masked pattern; each one
  that is unique in the new exe votes for the address its instruction points at.
- vtables: by RTTI name (vtable[-1] -> CompleteObjectLocator -> TypeDescriptor).
- struct offsets, opcodes and constants are not addresses: listed as "verify in game".

Nothing it prints is trusted until `cdmp_probe` checks it in game.

`test_port.py OLD.dll NEW.dll` measures it on two builds of any DLL with exports and RTTI.
On steamclient64.dll (0x6A70EF49 -> 0x6AD92AA7, every export moved 4.5-130 KB):
40/40 functions, 18/18 globals, 25/25 vtables, 0 wrong.
