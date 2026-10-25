$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$serverExe = Join-Path $root 'rust-basis-server\target\debug\basis-server-rs.exe'
$clientExe = Join-Path $root '.basis-test\upstream56-src\Basis Server\BasisNetworkClientConsole\BasisNetworkClientConsole\bin\Release\net10.0\BasisNetworkClientConsole.exe'
$work = Join-Path $root '.basis-test\headless56-run'
$serverLog = Join-Path $work 'server.log'
$clientLog = Join-Path $work 'client.log'
$clientErr = Join-Path $work 'client.err.log'

if (-not (Test-Path $clientExe)) { throw "missing protocol-56 client: $clientExe" }
New-Item -ItemType Directory -Force $work | Out-Null
Copy-Item (Join-Path $root 'ClientSimConfig.xml') (Join-Path $work 'ClientSimConfig.xml') -Force
[xml]$config = Get-Content (Join-Path $work 'ClientSimConfig.xml')
$config.Configuration.ClientCount = '2'
$config.Configuration.Port = '4397'
$config.Configuration.SimulateVoice = 'true'
$config.Save((Join-Path $work 'ClientSimConfig.xml'))

& cargo build --manifest-path (Join-Path $root 'rust-basis-server\Cargo.toml') -p basis-server | Out-Host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Remove-Item $serverLog, $clientLog, $clientErr -ErrorAction SilentlyContinue
$server = Start-Process -FilePath $serverExe -ArgumentList '--port=4397','--health-port=0','--no-file-support','--use-auth' -PassThru `
    -RedirectStandardOutput $serverLog -RedirectStandardError (Join-Path $work 'server.err.log') -WindowStyle Hidden
$client = $null
try {
    Start-Sleep -Milliseconds 800
    $client = Start-Process -FilePath $clientExe -ArgumentList '--chat-test','--scene-test','--ownership-test','--resource-test' -WorkingDirectory $work -PassThru `
        -RedirectStandardOutput $clientLog -RedirectStandardError $clientErr -WindowStyle Hidden
    Start-Sleep -Seconds 20

    $log = Get-Content $clientLog -Raw
    foreach ($pattern in @('\[CHAT\]','\[SCENE\]','\[OWNER\]','\[RESOURCE\]')) {
        if ($log -notmatch $pattern) { throw "missing client evidence: $pattern" }
    }

    Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue
    $client = $null
    Start-Sleep -Seconds 7
    $serverText = Get-Content $serverLog -Raw
    if ($serverText -notmatch 'Peer removed:') { throw 'missing peer removal evidence' }
    Write-Host 'PASS: protocol-56 headless chat/scene/ownership/resource'
}
catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path $clientLog) { Get-Content $clientLog -Tail 40 }
    if (Test-Path $serverLog) { Get-Content $serverLog -Tail 40 }
    exit 1
}
finally {
    if ($client -and -not $client.HasExited) { Stop-Process -Id $client.Id -Force -ErrorAction SilentlyContinue }
    Get-Process BasisNetworkClientConsole -ErrorAction SilentlyContinue | Stop-Process -Force
    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue }
}









