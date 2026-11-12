param(
    [string]$SdkRoot = $(if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { $env:ANDROID_HOME }),
    [string]$BuildToolsVersion = '35.0.0',
    [string]$KeystorePath,
    [string]$KeyAlias = 'local'
)
$ErrorActionPreference = 'Stop'
$moduleRoot = $PSScriptRoot
if (!$SdkRoot) { throw 'Set ANDROID_SDK_ROOT or ANDROID_HOME to your Android SDK directory.' }
if (!$env:JAVA_HOME) { throw 'Set JAVA_HOME to your JDK directory.' }
$jdkRoot = $env:JAVA_HOME
$buildTools = Join-Path $SdkRoot "build-tools\$BuildToolsVersion"
$androidJar = Join-Path $SdkRoot 'platforms\android-35\android.jar'
foreach ($required in @($androidJar, "$jdkRoot\bin\javac.exe", "$buildTools\aapt.exe", "$buildTools\d8.bat", "$buildTools\zipalign.exe", "$buildTools\apksigner.bat")) {
    if (!(Test-Path -LiteralPath $required)) { throw "Missing build prerequisite: $required" }
}
function Check-Result { if ($LASTEXITCODE -ne 0) { throw "Build command failed: $LASTEXITCODE" } }
New-Item -ItemType Directory -Force -Path "$moduleRoot\build\classes", "$moduleRoot\build\dex", "$moduleRoot\out", "$moduleRoot\lib", "$moduleRoot\.local" | Out-Null
$apiJar = "$moduleRoot\lib\xposed-api-82.jar"
$expectedApiHash = 'F48C635F1C7469FDEC0E00AD2EA0B7A6B2F5B55065784A35B7CA3A84615E8E25'
if (!(Test-Path -LiteralPath $apiJar)) {
    Invoke-WebRequest -Uri 'https://api.xposed.info/de/robv/android/xposed/api/82/api-82.jar' -OutFile $apiJar
}
if ((Get-FileHash -LiteralPath $apiJar -Algorithm SHA256).Hash -ne $expectedApiHash) { throw 'Xposed API checksum mismatch.' }
# Compile from a clean class directory so removed classes cannot enter a later APK.
if (Test-Path -LiteralPath "$moduleRoot\build\classes") {
    $classDir = [IO.Path]::GetFullPath("$moduleRoot\build\classes")
    if ($classDir -ne [IO.Path]::GetFullPath((Join-Path $moduleRoot 'build\classes'))) { throw 'Unexpected build path.' }
    Remove-Item -LiteralPath $classDir -Recurse -Force
    New-Item -ItemType Directory -Path $classDir | Out-Null
}
$sources = @(Get-ChildItem "$moduleRoot\src" -Recurse -Filter *.java | ForEach-Object FullName)
& "$jdkRoot\bin\javac.exe" --release 8 -encoding UTF-8 -classpath "$androidJar;$apiJar" -d "$moduleRoot\build\classes" @sources
Check-Result
& "$jdkRoot\bin\jar.exe" cf "$moduleRoot\build\classes.jar" -C "$moduleRoot\build\classes" .
Check-Result
& "$buildTools\d8.bat" --release --min-api 28 --lib $androidJar --classpath $apiJar --output "$moduleRoot\build\dex" "$moduleRoot\build\classes.jar"
Check-Result
& "$buildTools\aapt.exe" package -f -M "$moduleRoot\AndroidManifest.xml" -I $androidJar -A "$moduleRoot\assets" -F "$moduleRoot\build\unsigned.apk"
Check-Result
Push-Location "$moduleRoot\build\dex"
try { & "$buildTools\aapt.exe" add "$moduleRoot\build\unsigned.apk" classes.dex; Check-Result } finally { Pop-Location }
& "$buildTools\zipalign.exe" -f -p 4 "$moduleRoot\build\unsigned.apk" "$moduleRoot\build\aligned.apk"
Check-Result
if (!$KeystorePath) {
    $KeystorePath = "$moduleRoot\.local\signing.jks"
    $env:TLSFIX_STORE_PASS = 'android'
    $env:TLSFIX_KEY_PASS = 'android'
    if (!(Test-Path -LiteralPath $KeystorePath)) {
        & "$jdkRoot\bin\keytool.exe" -genkeypair -keystore $KeystorePath -storepass:env TLSFIX_STORE_PASS -keypass:env TLSFIX_KEY_PASS -alias $KeyAlias -dname 'CN=Local ChatGPT TLS Module' -keyalg RSA -keysize 2048 -validity 10000
        Check-Result
    }
}
if (!$env:TLSFIX_STORE_PASS) { throw 'Set TLSFIX_STORE_PASS for the selected keystore.' }
if (!$env:TLSFIX_KEY_PASS) { $env:TLSFIX_KEY_PASS = $env:TLSFIX_STORE_PASS }
$apk = "$moduleRoot\out\ChatGPT-TLS-Fix-1.0.apk"
& "$buildTools\apksigner.bat" sign --ks $KeystorePath --ks-pass env:TLSFIX_STORE_PASS --key-pass env:TLSFIX_KEY_PASS --ks-key-alias $KeyAlias --out $apk "$moduleRoot\build\aligned.apk"
Check-Result
& "$buildTools\apksigner.bat" verify --verbose $apk
Check-Result
$hash = (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$moduleRoot\out\SHA256SUMS.txt", "$hash  ChatGPT-TLS-Fix-1.0.apk`n", [Text.UTF8Encoding]::new($false))
Write-Output "APK: $apk"
