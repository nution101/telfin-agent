# Telfin Agent Installer for Windows
# Usage: irm https://raw.githubusercontent.com/nution101/telfin-agent/master/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "nution101/telfin-agent"
$BinaryName = "telfin-agent.exe"

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# Check for admin privileges (required for scheduled task)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Administrator privileges required. Requesting elevation..."

    # Save script to temp file and run elevated
    $scriptUrl = "https://raw.githubusercontent.com/$Repo/master/install.ps1"
    $tempScript = "$env:TEMP\telfin-install.ps1"

    try {
        Invoke-WebRequest -Uri $scriptUrl -OutFile $tempScript -UseBasicParsing
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`"" -Wait
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
        exit 0
    } catch {
        Write-Err "Failed to elevate. Please run PowerShell as Administrator and try again."
    }
}

# Get latest release version
Write-Info "Fetching latest version..."
try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
    $Version = $release.tag_name
    Write-Info "Latest version: $Version"
} catch {
    Write-Err "Failed to fetch latest version. Check your internet connection."
}

# Determine architecture
$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$AssetName = "telfin-windows-$Arch.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName"

# Create install directory
$InstallDir = "$env:LOCALAPPDATA\Telfin"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Download
Write-Info "Downloading telfin-agent $Version for windows/$Arch..."
$ZipPath = "$env:TEMP\telfin.zip"
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
} catch {
    Write-Err "Download failed. Check https://github.com/$Repo/releases"
}

# Extract
Write-Info "Extracting..."
$ExtractPath = "$env:TEMP\telfin-extract"
if (Test-Path $ExtractPath) { Remove-Item -Recurse -Force $ExtractPath }
Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

# Find and move binary
$Binary = Get-ChildItem -Path $ExtractPath -Filter "*.exe" -Recurse | Select-Object -First 1
if (-not $Binary) {
    Write-Err "Could not find telfin-agent.exe in archive"
}

# Stop existing process
Write-Info "Stopping existing telfin processes..."
Get-Process -Name "telfin-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# Install
Write-Info "Installing to $InstallDir..."
Copy-Item -Path $Binary.FullName -Destination "$InstallDir\telfin.exe" -Force

# Cleanup
Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $ExtractPath -Recurse -Force -ErrorAction SilentlyContinue

# Add to PATH if not already there
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Info "Adding to PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host ""
Write-Info "Binary installed to $InstallDir\telfin.exe"
Write-Host ""

# Run setup
Write-Info "Starting Telfin setup..."
Write-Host ""
& "$InstallDir\telfin.exe" install
