param(
    [switch]$NormalizeOnly
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$csharpExe = Join-Path $root '.basis-test\server\BasisNetworkConsole.exe'
$csharpWork = Join-Path $root '.basis-test\server'
$rustExe = Join-Path $root 'rust-basis-server\target\debug\basis-server-rs.exe'
$harness = Join-Path $root '.basis-test\harness\bin\Release\net10.0\BasisCompatHarness.dll'
$csharpLog = Join-Path $root '.basis-test\diff-csharp.log'
$csharpErr = Join-Path $root '.basis-test\diff-csharp.err.log'
$rustLog = Join-Path $root '.basis-test\diff-rust.log'
$rustErr = Join-Path $root '.basis-test\diff-rust.err.log'

function Stop-TestServer([string]$name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
}

function Invoke-Harness([string]$mode) {
    Write-Host "harness $mode"
    $process = Start-Process -FilePath 'dotnet' -ArgumentList @($harness, $mode, '--port=4396') -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(20000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "harness $mode timed out"
    }
    if ($process.ExitCode -ne 0) { throw "harness $mode failed with exit $($process.ExitCode)" }
}

function Run-Csharp([string]$log, [string]$err) {
    Remove-Item $log, $err -ErrorAction SilentlyContinue
    $oldPort = $env:SetPort
    $oldAuth = $env:UseAuth
    $oldIdentity = $env:UseAuthIdentity
    $oldTimeout = $env:AuthValidationTimeOutMiliseconds
    $oldFiles = $env:HasFileSupport
    try {
        $env:SetPort = '4396'
        $env:UseAuth = 'true'
        $env:UseAuthIdentity = 'true'
        $env:HasFileSupport = 'false'
        $env:AuthValidationTimeOutMiliseconds = '2000'
        $env:LogConnectionHandshake = 'true'
        $server = Start-Process -FilePath $csharpExe -WorkingDirectory $csharpWork -PassThru `
            -RedirectStandardOutput $log -RedirectStandardError $err -WindowStyle Hidden
    }
    finally {
        $env:SetPort = $oldPort
        $env:UseAuth = $oldAuth
        $env:UseAuthIdentity = $oldIdentity
        $env:HasFileSupport = $oldFiles
        $env:AuthValidationTimeOutMiliseconds = $oldTimeout
        $env:LogConnectionHandshake = $null
    }
    Start-Sleep -Milliseconds 1800
    Invoke-Harness '--connect-only'
    Invoke-Harness '--bad-password'
    Invoke-Harness '--bad-auth'
    Invoke-Harness '--auth-timeout'
    Start-Sleep -Milliseconds 800
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
    Stop-TestServer 'BasisNetworkConsole'
}

function Run-Rust([string]$log, [string]$err) {
    Remove-Item $log, $err -ErrorAction SilentlyContinue
    $server = Start-Process -FilePath $rustExe -WorkingDirectory $root -PassThru `
        -ArgumentList '--port=4396', '--use-auth', '--health-port=0', '--no-file-support', '--no-avatar-reduction', '--auth-timeout-ms=2000', '--log-connection-handshake' `
        -RedirectStandardOutput $log -RedirectStandardError $err -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
    Invoke-Harness '--connect-only'
    Invoke-Harness '--bad-password'
    Invoke-Harness '--bad-auth'
    Invoke-Harness '--auth-timeout'
    Start-Sleep -Milliseconds 800
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}

function Normalize([string]$path) {
    $patterns = @(
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] no logs will be saved$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Server Booting$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Loaded Admins 0 $',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] DidAuthIdentity initialized\.$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Listening on UDP port 4396$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\]   IPv4 bind: 0\.0\.0\.0$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Server Worker Threads Booted$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Default library loaded with 0 item\(s\)\.$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Peer connected: [0-9]+$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Peer removed: [0-9]+$',
        '^\[[0-9]{2}:[0-9]{2}\] \[ERROR\] Passwords do not match, user is rejected$',
        '^\[[0-9]{2}:[0-9]{2}\] \[ERROR\] Rejected for reason: Authentication failed, Auth rejected$',
        '^\[[0-9]{2}:[0-9]{2}\] \[ERROR\] Authentication failed for did:key:.+\.$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Peer [0-9]+ was not in AuthenticatedPeers .+$',
        '^\[[0-9]{2}:[0-9]{2}\] \[ERROR\] Rejected after accept with reason: was unable to authenticate!$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Authentication timeout for did:key:.+\.$',
        '^\[[0-9]{2}:[0-9]{2}\] \[ERROR\] Rejected after accept with reason: Authentication timeout$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Processing connection from peer [0-9]+\.$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] Sending out Writer with size : [0-9]+$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] \[basisctl\] Control socket listening at .+$',
        '^\[[0-9]{2}:[0-9]{2}\] \[INFO\] \[P2P\] Broker initialised\.$'
    )
    $lines = Get-Content $path | Where-Object { $line = $_; $patterns | Where-Object { $line -match $_ } }
    return $lines | ForEach-Object {
        $line = $_ -replace '^\[\d{2}:\d{2}\]', '[TIME]'
        $line = $line -replace 'did:key:[A-Za-z0-9]+', 'did:key:<DID>'
        $line = $line -replace 'Peer [0-9]+', 'Peer <ID>'
        $line = $line -replace 'Player [0-9]+', 'Player <ID>'
        $line = $line -replace '\[basisctl\] Control socket listening at .+$', '[basisctl] Control socket listening at <SOCKET>'
        $line = $line -replace '\[(CPU|POP|BSR|CPU/POP)\] .+$', '[$1] <DETAIL>'
        $line
    }
}

if (-not $NormalizeOnly) {
    Write-Host 'Building Rust server...'
    cargo build --manifest-path (Join-Path $root 'rust-basis-server\Cargo.toml') -p basis-server | Out-Host
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Stop-TestServer 'BasisNetworkConsole'
    Stop-TestServer 'basis-server-rs'

    Write-Host 'Capturing C# oracle...'
    Run-Csharp $csharpLog $csharpErr
    Write-Host 'Capturing Rust...'
    Run-Rust $rustLog $rustErr
}

$csharp = @(Normalize $csharpLog)
$rust = @(Normalize $rustLog)

Write-Host '--- C# shared lines ---'
$csharp | ForEach-Object { Write-Host $_ }
Write-Host '--- Rust shared lines ---'
$rust | ForEach-Object { Write-Host $_ }

if ($csharp.Count -eq 0) { throw 'C# oracle produced no shared lines' }
if ($rust.Count -eq 0) { throw 'Rust produced no shared lines' }
if (($csharp -join "`n") -ne ($rust -join "`n")) {
    Write-Host 'FAIL: normalized shared log sequences differ' -ForegroundColor Red
    exit 1
}

Write-Host "PASS: $($rust.Count) normalized shared log records match the C# oracle"
exit 0













