param(
  [string]$Exe = "src-tauri\target\release\zcode-hub.exe",
  [int]$WaitSeconds = 8
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$exePath = Join-Path $root $Exe
if (-not (Test-Path $exePath)) {
  throw "Release binary not found at $exePath. Run 'cargo build --release' in src-tauri first."
}

$already = Get-Process zcode-hub -ErrorAction SilentlyContinue
$started = $null
if (-not $already) {
  $started = Start-Process -FilePath $exePath -PassThru
  Start-Sleep -Seconds $WaitSeconds
} else {
  Write-Warning "ZCode Hub is already running; reading the latest startup log and current memory without restarting it."
}

$log = Join-Path $env:APPDATA "zcode-hub\startup.log"
$last = $null
if (Test-Path $log) {
  $line = Get-Content $log -Tail 1
  try { $last = $line | ConvertFrom-Json } catch { $last = $null }
}

$proc = Get-Process zcode-hub -ErrorAction SilentlyContinue |
  Sort-Object StartTime -Descending | Select-Object -First 1

[pscustomobject]@{
  startup_ms     = if ($last) { $last.ms } else { $null }
  version        = if ($last) { $last.version } else { $null }
  logged_at      = if ($last) { $last.ts } else { $null }
  working_set_mb = if ($proc) { [math]::Round($proc.WorkingSet64 / 1MB, 1) } else { $null }
  private_mb     = if ($proc) { [math]::Round($proc.PrivateMemorySize64 / 1MB, 1) } else { $null }
  pid            = if ($proc) { $proc.Id } else { $null }
  measured_at    = (Get-Date).ToString("o")
} | ConvertTo-Json -Depth 4

if ($started) { Stop-Process -Id $started.Id -Force -ErrorAction SilentlyContinue }
