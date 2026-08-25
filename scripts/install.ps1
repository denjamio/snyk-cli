$ErrorActionPreference = "Stop"

$Repo    = if ($env:SNYK_CLI_REPO)         { $env:SNYK_CLI_REPO }       else { "denjamio/snyk-cli" }
$Bin     = "snyk"
$BaseURL = if ($env:SNYK_CLI_BASE_URL)     { $env:SNYK_CLI_BASE_URL }   else { "https://github.com/$Repo" }
$APIURL  = if ($env:SNYK_CLI_API_URL)      { $env:SNYK_CLI_API_URL }    else { "https://api.github.com/repos/$Repo/releases/latest" }
$Dest    = if ($env:SNYK_CLI_INSTALL_DIR)  { $env:SNYK_CLI_INSTALL_DIR }
           elseif ($env:LOCALAPPDATA)          { Join-Path $env:LOCALAPPDATA "Programs\$Bin" }
           else                                { Join-Path $HOME ".local/bin" }

function Fail($msg) { [Console]::Error.WriteLine("error: $msg"); exit 1 }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { Fail "unsupported architecture '$env:PROCESSOR_ARCHITECTURE' - grab a binary from $BaseURL/$Bin/releases" }
}

$version = $env:SNYK_CLI_VERSION
if (-not $version) {
    try { $rel = Invoke-RestMethod -Uri $APIURL -UseBasicParsing } catch { Fail "could not query latest release: $_" }
    $version = $rel.tag_name
}
if (-not $version) { Fail "could not determine latest release (set SNYK_CLI_VERSION)" }
$verNum = $version.TrimStart("v")

$asset = "${bin}_${verNum}_windows_${arch}.zip"
$dl    = "$BaseURL/releases/download/$version"
$tmp   = New-Item -ItemType Directory -Path (Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString()))

try {
    Write-Host "Installing $Bin $version (windows/$arch)..."
    Write-Host "Downloading $dl/$asset"
    $zipPath = Join-Path $tmp $asset
    try { Invoke-WebRequest -Uri "$dl/$asset" -OutFile $zipPath -UseBasicParsing } catch { Fail "download failed: $dl/$asset" }

    $sumPath = Join-Path $tmp "checksums.txt"
    try { Invoke-WebRequest -Uri "$dl/checksums.txt" -OutFile $sumPath -UseBasicParsing } catch { Fail "download failed: checksums.txt" }

    $want = $null
    foreach ($line in Get-Content $sumPath) {
        $parts = $line.Trim() -split "\s+", 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $asset) { $want = $parts[0]; break }
    }
    if (-not $want) { Fail "checksum for $asset not found in checksums.txt" }

    $got = (Get-FileHash -Algorithm SHA256 $zipPath).Hash.ToLower()
    if ($got -ne $want.ToLower()) { Fail "checksum mismatch for $asset" }

    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    $exe = Join-Path $tmp "$Bin.exe"
    if (-not (Test-Path $exe)) { Fail "archive did not contain $Bin.exe" }

    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    Move-Item -Force -Path $exe -Destination (Join-Path $Dest "$Bin.exe")
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ";") -notcontains $Dest) {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$Dest", "User")
    Write-Host "note: added $Dest to your user PATH - restart your terminal to take effect"
}

try { & (Join-Path $Dest "$Bin.exe") version } catch { Write-Host "(skipped post-install version check)" }
Write-Host "Installed to $(Join-Path $Dest "$Bin.exe")"
Write-Host "tip: snyk skill install --global installs the agent skill"
