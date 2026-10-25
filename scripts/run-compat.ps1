$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$serverExe = Join-Path $root 'rust-basis-server\target\debug\basis-server-rs.exe'
$harness = Join-Path $root '.basis-test\harness\bin\Release\net10.0\BasisCompatHarness.dll'
$stdout = Join-Path $root '.basis-test\compat-server.out.log'
$stderr = Join-Path $root '.basis-test\compat-server.err.log'

Write-Host 'Building Rust server...'
cargo build --manifest-path (Join-Path $root 'rust-basis-server\Cargo.toml') | Out-Host
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not (Test-Path $serverExe)) { throw "missing server binary: $serverExe" }
if (-not (Test-Path $harness)) { throw "missing harness: $harness (build .basis-test\harness first)" }

Remove-Item $stdout, $stderr -ErrorAction SilentlyContinue
$server = Start-Process -FilePath $serverExe -ArgumentList '--port=4396','--use-auth','--health-port=10667','--health-host=127.0.0.1','--no-file-support' -PassThru `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden

try {
    Start-Sleep -Milliseconds 800
    $health = Invoke-RestMethod -Uri 'http://127.0.0.1:10667/health' -TimeoutSec 3
    if (-not $health.listening -or $health.capacity -lt 1) {
        throw 'health endpoint did not report a listening server'
    }
    if ($health.version -ne '56' -or -not $health.currentTime -or -not $health.startTime -or -not $health.process -or -not $health.memory) {
        throw 'health endpoint is missing required fields'
    }
    if ($health.process.rssBytes -lt 1) {
        throw 'health endpoint did not report process RSS'
    }
    $players = Invoke-RestMethod -Uri 'http://127.0.0.1:10667/api/players' -TimeoutSec 3
    if ($null -eq $players.players) {
        throw 'players endpoint did not return a players array'
    }
    $worlds = Invoke-RestMethod -Uri 'http://127.0.0.1:10667/api/worlds' -TimeoutSec 3
    if ($null -eq $worlds.worlds) {
        throw 'worlds endpoint did not return a worlds array'
    }
    $loadedWorld = Invoke-RestMethod -Uri 'http://127.0.0.1:10667/api/worlds' -Method Post -ContentType 'application/json' -Body '{"url":"https://example.invalid/world.bee","password":"compat","persistent":false}' -TimeoutSec 3
    if (-not $loadedWorld.netId) { throw 'world load did not return a netId' }
    Start-Sleep -Milliseconds 800
    $worldList = Invoke-RestMethod -Uri 'http://127.0.0.1:10667/api/worlds' -TimeoutSec 3
    if (-not ($worldList.worlds | Where-Object { $_.netId -eq $loadedWorld.netId })) { throw 'loaded world missing from list' }
    Invoke-RestMethod -Uri ("http://127.0.0.1:10667/api/worlds/" + $loadedWorld.netId) -Method Delete -TimeoutSec 3 | Out-Null
    $announce = Invoke-RestMethod -Uri 'http://127.0.0.1:10667/api/announce' -Method Post -ContentType 'application/json' -Body '{"message":"compat"}' -TimeoutSec 3
    if (-not $announce.ok) { throw 'announce endpoint failed' }

    $badJson = (& curl.exe -s -o NUL -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary '{"url":' 'http://127.0.0.1:10667/api/worlds').Trim()
    if ($badJson -ne '400') { throw "invalid JSON returned $badJson" }
    $noPassword = (& curl.exe -s -o NUL -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary '{"url":"https://example.invalid/world.bee"}' 'http://127.0.0.1:10667/api/worlds').Trim()
    if ($noPassword -ne '400') { throw "missing password returned $noPassword" }
    $badStrategy = (& curl.exe -s -o NUL -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary '{"url":"https://example.invalid/world.bee","password":"compat","strategy":"bogus"}' 'http://127.0.0.1:10667/api/worlds').Trim()
    if ($badStrategy -ne '400') { throw "unknown strategy returned $badStrategy" }
    $missingWorld = (& curl.exe -s -o NUL -w '%{http_code}' -X DELETE 'http://127.0.0.1:10667/api/worlds/missing').Trim()
    if ($missingWorld -ne '404') { throw "missing world delete returned $missingWorld" }
    $playersPost = (& curl.exe -s -i -X POST 'http://127.0.0.1:10667/api/players') -join "`n"
    if ($playersPost -notmatch '405 Method Not Allowed' -or $playersPost -notmatch 'Allow: GET') {
        throw 'players POST did not return 405 with Allow: GET'
    }
    $oversizePath = Join-Path (Get-Location) '.basis-test\oversize.json'
    [IO.File]::WriteAllText($oversizePath, '{"url":"' + ('a' * 1048600) + '"}')
    try {
        $oversize = (& curl.exe -s -o NUL -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "@$oversizePath" 'http://127.0.0.1:10667/api/worlds').Trim()
        if ($oversize -ne '413') { throw "oversize body returned $oversize" }
    } finally {
        Remove-Item $oversizePath -Force -ErrorAction SilentlyContinue
    }
    $healthResponse = Invoke-WebRequest -Uri 'http://127.0.0.1:10667/health' -UseBasicParsing -TimeoutSec 3
    if ($healthResponse.Headers['Cache-Control'] -ne 'no-store, max-age=0') {
        throw 'health endpoint is missing the C# cache header'
    }
    if ($healthResponse.Headers['X-Content-Type-Options'] -ne 'nosniff') {
        throw 'health endpoint is missing the C# content-type hardening header'
    }
    try {
        Invoke-WebRequest -Uri 'http://127.0.0.1:10667/health' -Method Post -UseBasicParsing -TimeoutSec 3 | Out-Null
        throw 'health endpoint accepted POST'
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 405) { throw }
    }
    try {
        Invoke-WebRequest -Uri 'http://127.0.0.1:10667/nope' -UseBasicParsing -TimeoutSec 3 | Out-Null
        throw 'health endpoint accepted an unknown path'
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 404) { throw }
    }
    & dotnet $harness --server-info --port=4396 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'server-info query failed' }
    Start-Sleep -Milliseconds 600
    & dotnet $harness --server-info-litenet --port=4396 | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'LiteNetLib server-info query failed' }
    & dotnet $harness
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        & dotnet $harness --late-join
        $code = $LASTEXITCODE
    }
    if ($code -eq 0) {
        & dotnet $harness --departure --port=4396
        $code = $LASTEXITCODE
    }
    if ($code -eq 0) {
        & dotnet $harness --duplicate-auth --port=4396
        $code = $LASTEXITCODE
    }
    if ($code -eq 0) {
        & dotnet $harness --bad-password
        $code = $LASTEXITCODE
    }
    if ($code -eq 0) {
        & dotnet $harness --reduction
        $code = $LASTEXITCODE
    }
    if ($code -ne 0) {
        Write-Host '--- server output ---'
        if (Test-Path $stdout) { Get-Content $stdout -Tail 40 }
        if (Test-Path $stderr) { Get-Content $stderr -Tail 40 }
    }
    exit $code
}
finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}














