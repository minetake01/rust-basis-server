$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$serverExe = Join-Path $root 'rust-basis-server\target\debug\basis-server-rs.exe'
$harness = Join-Path $root '.basis-test\harness\bin\Release\net10.0\BasisCompatHarness.dll'
$stdout = Join-Path $root '.basis-test\log-compat-server.log'
$stderr = Join-Path $root '.basis-test\log-compat-server.err.log'

Write-Host 'Building Rust server...'
cargo build --manifest-path (Join-Path $root 'rust-basis-server\Cargo.toml') -p basis-server | Out-Host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Remove-Item $stdout, $stderr -ErrorAction SilentlyContinue
$server = Start-Process -FilePath $serverExe `
    -ArgumentList '--port=4396', '--health-port=0', '--no-file-support', '--use-auth' `
    -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden

function Wait-ForLine([string]$pattern, [int]$seconds = 5) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $stdout) {
            $match = Get-Content $stdout | Select-String -Pattern $pattern
            if ($match) { return $true }
        }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

function Assert-Line([string]$pattern, [string]$label) {
    if (-not (Wait-ForLine $pattern)) {
        Write-Host "FAIL: missing log line: $label" -ForegroundColor Red
        exit 1
    }
}

try {
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] no logs will be saved$' 'no logs will be saved'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Server Booting$' 'Server Booting'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Loaded Admins 0 $' 'Loaded Admins'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] DidAuthIdentity initialized\.$' 'DidAuthIdentity initialized'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Listening on UDP port 4396$' 'Listening on UDP port'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\]   IPv4 bind: 0\.0\.0\.0$' 'IPv4 bind'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Server Worker Threads Booted$' 'Server Worker Threads Booted'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Default library loaded with 0 item\(s\)\.$' 'Default library'

    & dotnet $harness | Out-Host
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Peer connected: 0$' 'Peer connected: 0'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Peer connected: 1$' 'Peer connected: 1'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Peer removed: 0$' 'Peer removed: 0'
    Assert-Line '^\[\d{2}:\d{2}\] \[INFO\] Peer removed: 1$' 'Peer removed: 1'

    & dotnet $harness --bad-password | Out-Host
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Assert-Line '^\[\d{2}:\d{2}\] \[ERROR\] Passwords do not match, user is rejected$' 'password rejection'
    Assert-Line '^\[\d{2}:\d{2}\] \[ERROR\] Rejected for reason: Authentication failed, Auth rejected$' 'rejection reason'

    $lines = Get-Content $stdout
    if ($lines | Select-String -Pattern 'INFO basis_server_rs::|WARN basis_server_rs::') {
        Write-Host 'FAIL: env_logger-style module prefixes leaked into the external log' -ForegroundColor Red
        exit 1
    }
    $passwordRejections = ($lines | Select-String -Pattern '^\[\d{2}:\d{2}\] \[ERROR\] Passwords do not match, user is rejected$').Count
    if ($passwordRejections -ne 1) {
        Write-Host "FAIL: expected one password rejection log, got $passwordRejections" -ForegroundColor Red
        exit 1
    }

    $failOut = Join-Path $root '.basis-test\log-compat-bind.out.log'
    $failErr = Join-Path $root '.basis-test\log-compat-bind.err.log'
    Remove-Item $failOut, $failErr -ErrorAction SilentlyContinue
    $second = Start-Process -FilePath $serverExe -ArgumentList '--port=4396', '--health-port=0', '--no-file-support' -PassThru `
        -RedirectStandardOutput $failOut -RedirectStandardError $failErr -WindowStyle Hidden
    Wait-Process -Id $second.Id -Timeout 5 -ErrorAction SilentlyContinue
    $bindLine = Get-Content $failOut -ErrorAction SilentlyContinue | Select-String -Pattern '^\[\d{2}:\d{2}\] \[ERROR\] Not listening: UDP port 4396 could not be bound\.'
    if (-not $bindLine) {
        Write-Host 'FAIL: bind failure did not produce the C# error line' -ForegroundColor Red
        exit 1
    }

    Write-Host 'PASS: log format, startup, connect, disconnect, rejection and bind-failure logs match the C# shape'
    exit 0
}
finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}



