param(
    [string]$JdkRoot = $env:JAVA_HOME,
    [string]$FixturePath
)
$ErrorActionPreference = 'Stop'
if (!$JdkRoot) { throw 'Set JAVA_HOME or pass -JdkRoot to a Java 8+ JDK.' }
$moduleRoot = $PSScriptRoot
$testRoot = [IO.Path]::GetFullPath((Join-Path $moduleRoot 'build\host-tests'))
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $moduleRoot 'build\host-tests'))
if ($testRoot -ne $expectedRoot -or !$testRoot.StartsWith([IO.Path]::GetFullPath($moduleRoot) + [IO.Path]::DirectorySeparatorChar)) { throw 'Unexpected test output path.' }
if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $testRoot 'classes') -Force | Out-Null
function Assert-Command { if ($LASTEXITCODE -ne 0) { throw "Host test command failed: $LASTEXITCODE" } }
if (!$FixturePath) {
    $FixturePath = Join-Path $testRoot 'fixture.der'
    $testKeystore = Join-Path $testRoot 'fixture.jks'
    & "$JdkRoot\bin\keytool.exe" -genkeypair -alias fixture -keystore $testKeystore -storepass test-only -keypass test-only -dname 'CN=TLSFIX HOST TEST,O=Local Fixture' -keyalg RSA -keysize 2048 -validity 2 -noprompt
    Assert-Command
    & "$JdkRoot\bin\keytool.exe" -exportcert -alias fixture -keystore $testKeystore -storepass test-only -file $FixturePath
    Assert-Command
}
$sources = @(
    Get-ChildItem -LiteralPath (Join-Path $moduleRoot 'tests') -Recurse -Filter *.java | ForEach-Object FullName
    Get-ChildItem -LiteralPath (Join-Path $moduleRoot 'src') -Recurse -Filter *.java | Where-Object Name -notin @('DiagnosticSelfTest.java','TransportErrorGuard.java') | ForEach-Object FullName
)
& "$JdkRoot\bin\javac.exe" --release 8 -encoding UTF-8 -d "$testRoot\classes" @sources
Assert-Command
$eventsPath = Join-Path $testRoot 'events.jsonl'
& "$JdkRoot\bin\java.exe" -ea -cp "$testRoot\classes" local.chatgpt.tlsfix.HookBehaviorTest ([IO.Path]::GetFullPath($FixturePath)) $eventsPath
Assert-Command
$events = @(Get-Content -LiteralPath $eventsPath -Encoding UTF8 | ForEach-Object { ConvertFrom-Json -InputObject $_ -ErrorAction Stop })
if (!$events.Count) { throw 'No structured event records captured.' }
foreach ($event in $events) {
    if ($event.schema -ne 1 -or !$event.session -or !$event.event -or !$event.outcome) { throw 'Incomplete structured event.' }
    if ($event.source -notin @('live','self_test')) { throw 'Missing test/live source distinction.' }
    if ($event.leaf -and ($event.leaf.sha256 -notmatch '^[0-9a-f]{64}$' -or !$event.leaf.subject -or !$event.leaf.issuer)) { throw 'Incomplete certificate evidence.' }
}
if (!($events | Where-Object { $_.event -eq 'verification_failed' -and $_.leaf })) { throw 'No original failed-certificate metadata captured.' }
Write-Output "PASS structured JSON and certificate fields: $($events.Count) sink records parsed; duplicate records from the two sinks are expected."
& "$JdkRoot\bin\java.exe" -ea -cp "$testRoot\classes" local.chatgpt.tlsfix.TransportGuardTest
Assert-Command
