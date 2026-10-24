# Puts the site and the signed launcher live at cdmp.breakneckhosting.com.
# Run AFTER the source is public on GitHub (GPL: the exe and its source go out together).
#
#   powershell -ExecutionPolicy Bypass -File C:\cdmp\deploy\deploy_site.ps1
#
# Copies site\ + dist\launcher\CDMP-Launcher.exe to C:\wwwroot\cdmp, installs the
# nginx vhost, tests the config and reloads nginx as SYSTEM (no downtime).

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$web = 'C:\wwwroot\cdmp'
$exe = Join-Path $root 'dist\launcher\CDMP-Launcher.exe'
$vhost = 'C:\BtSoft\nginx\conf\vhost\cdmp.conf'

if ((Get-AuthenticodeSignature $exe).Status -ne 'Valid') { throw "$exe is not signed" }

New-Item -ItemType Directory -Force "$web\download" | Out-Null
Copy-Item (Join-Path $root 'site\index.html') $web -Force
Copy-Item $exe "$web\download\CDMP-Launcher.exe" -Force
(Get-FileHash "$web\download\CDMP-Launcher.exe").Hash.ToLower() + '  CDMP-Launcher.exe' |
    Set-Content "$web\download\SHA256SUMS.txt" -Encoding ascii
Copy-Item (Join-Path $PSScriptRoot 'cdmp.conf') $vhost -Force

Push-Location C:\BtSoft\nginx
& .\nginx.exe -t
$ok = $LASTEXITCODE -eq 0
Pop-Location
if (-not $ok) { Remove-Item $vhost; throw 'nginx -t failed; vhost removed, nothing reloaded' }

$cmd = 'cmd /c cd /d C:\BtSoft\nginx && nginx.exe -s reload'
schtasks /create /tn 'nginx-reload-once' /tr $cmd /sc once /st 23:59 /ru SYSTEM /rl HIGHEST /f | Out-Null
schtasks /run /tn 'nginx-reload-once' | Out-Null
Start-Sleep -Seconds 3
schtasks /delete /tn 'nginx-reload-once' /f | Out-Null

$r = Invoke-WebRequest -Uri 'http://127.0.0.1/' -Headers @{ Host = 'cdmp.breakneckhosting.com' } -UseBasicParsing
"Site answers locally: HTTP $($r.StatusCode), $($r.Content.Length) bytes"
'Live once DNS has: cdmp.breakneckhosting.com -> 66.51.99.113 (proxied).'
