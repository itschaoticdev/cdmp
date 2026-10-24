# Signs the built mod and tools with Authenticode (signtool from the
# Windows SDK installed with the Build Tools) and checks each signature.
#
#   .\scripts\sign.ps1 -Thumbprint <sha1>          # certificate in the Windows store
#   .\scripts\sign.ps1 -Pfx cert.pfx -Password x   # certificate file
#   .\scripts\sign.ps1 ... -Config Release
#
# Nothing to sign with yet: a self-signed certificate is trusted only on the
# PC that made it, so players would still see the warnings. Use a real code
# signing certificate (OV/EV, or Azure Trusted Signing).

param(
    [string]$Thumbprint,
    [string]$Pfx,
    [string]$Password,
    [ValidateSet('Debug', 'Release', 'RelWithDebInfo')]
    [string]$Config = 'RelWithDebInfo',
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
$bin = Join-Path $root "build\bin\$Config"

if (-not $Thumbprint -and -not $Pfx) { throw 'Give -Thumbprint or -Pfx (see the top of this script)' }
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) { throw 'signtool.exe not found (Windows SDK)' }

$files = @('cdmp.asi', 'cdmp_relay.exe', 'cdmp_peer.exe', 'cdmp_host.exe', 'cdmp_probe.exe') |
    ForEach-Object { Join-Path $bin $_ } | Where-Object { Test-Path $_ }
if (-not $files) { throw "Nothing built in $bin (run scripts\build.ps1 first)" }

$cert = if ($Thumbprint) { @('/sha1', $Thumbprint) } else { @('/f', $Pfx) + $(if ($Password) { @('/p', $Password) } else { @() }) }
& $signtool sign @cert /fd sha256 /tr $TimestampUrl /td sha256 /d 'Crimson Desert Multiplayer' @files
if ($LASTEXITCODE) { throw "signtool sign failed ($LASTEXITCODE)" }
& $signtool verify /pa /q @files
if ($LASTEXITCODE) { throw "signature check failed ($LASTEXITCODE)" }
Write-Host "Signed: $($files -join ', ')"
