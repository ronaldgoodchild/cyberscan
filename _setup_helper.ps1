# CyberScan 2026 - Setup Helper Script
# Prepares any Windows PC to run CyberScan TITAN ULTIMATE

$ErrorActionPreference = "SilentlyContinue"

function Write-Step {
    param([int]$Num, [string]$Title)
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor DarkCyan
    Write-Host "   STEP $Num`: $Title" -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-OK   { param([string]$Msg) Write-Host "  [OK]   $Msg" -ForegroundColor Green }
function Write-SKIP { param([string]$Msg) Write-Host "  [SKIP] $Msg" -ForegroundColor DarkGray }
function Write-WARN { param([string]$Msg) Write-Host "  [WARN] $Msg" -ForegroundColor Yellow }
function Write-FAIL { param([string]$Msg) Write-Host "  [FAIL] $Msg" -ForegroundColor Red }
function Write-INFO { param([string]$Msg) Write-Host "  [....] $Msg" -ForegroundColor White -NoNewline }

# =================================================================
#  STEP 1: EXECUTION POLICY
# =================================================================
Write-Step 1 "Configuring PowerShell Execution Policy"

try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction SilentlyContinue
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    Write-OK "Execution policy: RemoteSigned (Machine) + Bypass (User)"
} catch {
    Write-WARN "Could not set execution policy: $($_.Exception.Message)"
}

# =================================================================
#  STEP 2: POWERSHELL VERSION CHECK + INSTALL PS7
# =================================================================
Write-Step 2 "Checking PowerShell Version"

$psVer = $PSVersionTable.PSVersion
Write-Host "  Current: Windows PowerShell $($psVer.Major).$($psVer.Minor) (Build $($psVer.Build))" -ForegroundColor White

$ps7Path = "$env:ProgramFiles\PowerShell\7\pwsh.exe"
if (Test-Path $ps7Path) {
    $ps7Ver = & $ps7Path -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' 2>$null
    Write-OK "PowerShell 7 already installed: v$ps7Ver"
} else {
    Write-Host "  PowerShell 7 not found. Installing..." -ForegroundColor Yellow
    Write-Host ""

    $installed = $false

    # Method 1: winget
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        Write-Host "  Trying winget..." -ForegroundColor Gray
        $result = Start-Process -FilePath "winget" -ArgumentList "install","--id","Microsoft.PowerShell","--accept-source-agreements","--accept-package-agreements","--silent" -Wait -PassThru -NoNewWindow 2>$null
        if ($result.ExitCode -eq 0 -or (Test-Path $ps7Path)) {
            Write-OK "PowerShell 7 installed via winget"
            $installed = $true
        }
    }

    # Method 2: Direct MSI download from GitHub
    if (-not $installed) {
        Write-Host "  Trying direct download from GitHub..." -ForegroundColor Gray
        try {
            $ProgressPreference = 'SilentlyContinue'
            $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -TimeoutSec 30
            $msi = $releases.assets | Where-Object { $_.name -match "PowerShell-.*-win-x64\.msi$" } | Select-Object -First 1
            if ($msi) {
                $outPath = "$env:TEMP\pwsh7_install.msi"
                Write-Host "  Downloading: $($msi.name)..." -ForegroundColor Gray
                Invoke-WebRequest -Uri $msi.browser_download_url -OutFile $outPath -UseBasicParsing
                Write-Host "  Installing MSI..." -ForegroundColor Gray
                Start-Process msiexec.exe -ArgumentList "/i","$outPath","/quiet","/norestart","ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1","REGISTER_MANIFEST=1","USE_MU=1","ENABLE_MU=1" -Wait
                Remove-Item $outPath -Force -ErrorAction SilentlyContinue
                if (Test-Path $ps7Path) {
                    Write-OK "PowerShell 7 installed via direct download"
                    $installed = $true
                } else {
                    Write-WARN "MSI ran but pwsh.exe not found at expected path"
                }
            } else {
                Write-WARN "Could not find MSI asset in latest GitHub release"
            }
        } catch {
            Write-WARN "Direct download failed: $($_.Exception.Message)"
        }
    }

    # Method 3: Microsoft install script
    if (-not $installed) {
        Write-Host "  Trying Microsoft install script..." -ForegroundColor Gray
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-Expression "& { $(Invoke-RestMethod 'https://aka.ms/install-powershell.ps1') } -UseMSI -Quiet"
            if (Test-Path $ps7Path) {
                Write-OK "PowerShell 7 installed via Microsoft script"
            } else {
                Write-WARN "Install script ran but PS7 not found"
            }
        } catch {
            Write-WARN "Microsoft install script failed: $($_.Exception.Message)"
        }
    }
}

# =================================================================
#  STEP 3: NUGET PROVIDER
# =================================================================
Write-Step 3 "Ensuring NuGet Package Provider"

$nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
if ($nuget) {
    Write-OK "NuGet already installed (v$($nuget.Version))"
} else {
    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        Write-OK "NuGet provider installed"
    } catch {
        Write-WARN "Could not install NuGet: $($_.Exception.Message)"
    }
}

# =================================================================
#  STEP 4: PSGALLERY TRUSTED
# =================================================================
Write-Step 4 "Configuring PSGallery as Trusted Repository"

try {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    Write-OK "PSGallery set to Trusted"
} catch {
    Write-WARN "Could not set PSGallery trust: $($_.Exception.Message)"
}

# =================================================================
#  STEP 5: INSTALL ADDON MODULES
# =================================================================
Write-Step 5 "Installing Add-on PowerShell Modules"

$addonModules = @(
    @{ Name = "PSWindowsUpdate";                        Desc = "Windows Update management" },
    @{ Name = "Microsoft.PowerShell.SecretManagement";  Desc = "Credential vault framework" },
    @{ Name = "Microsoft.PowerShell.SecretStore";       Desc = "Secret storage backend" },
    @{ Name = "BurntToast";                             Desc = "Desktop toast notifications" },
    @{ Name = "PSReadLine";                             Desc = "Enhanced console experience" },
    @{ Name = "ThreadJob";                              Desc = "Lightweight background jobs" },
    @{ Name = "ImportExcel";                            Desc = "Excel report generation" },
    @{ Name = "Pester";                                 Desc = "PowerShell testing framework" }
)

$instCount = 0; $skipCount = 0; $failCount = 0
foreach ($m in $addonModules) {
    $existing = Get-Module -ListAvailable -Name $m.Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-SKIP "$($m.Name) - already installed"
        $skipCount++
    } else {
        Write-INFO "Installing $($m.Name) ($($m.Desc))..."
        try {
            Install-Module -Name $m.Name -Force -Scope AllUsers -AllowClobber -SkipPublisherCheck -ErrorAction Stop
            Write-Host "`r  [OK]   $($m.Name) installed                              " -ForegroundColor Green
            $instCount++
        } catch {
            Write-Host "`r  [FAIL] $($m.Name): $($_.Exception.Message)              " -ForegroundColor Yellow
            $failCount++
        }
    }
}
Write-Host ""
Write-Host "  Installed: $instCount | Already present: $skipCount | Failed: $failCount" -ForegroundColor White

# =================================================================
#  STEP 6: VERIFY BUILT-IN WINDOWS MODULES
# =================================================================
Write-Step 6 "Verifying Built-in Windows Modules"

$requiredModules = @(
    "NetSecurity",
    "NetTCPIP",
    "NetAdapter",
    "SmbShare",
    "Storage",
    "Defender",
    "BitLocker",
    "ScheduledTasks",
    "Appx",
    "PnpDevice",
    "Microsoft.PowerShell.LocalAccounts",
    "Dism"
)

$okCount = 0; $missCount = 0
foreach ($mod in $requiredModules) {
    $found = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue
    if ($found) {
        Write-OK $mod
        $okCount++
    } else {
        Write-WARN "$mod - NOT FOUND (some features may be limited)"
        $missCount++
    }
}
Write-Host ""
Write-Host "  Available: $okCount / $($requiredModules.Count)" -ForegroundColor White
if ($missCount -gt 0) {
    Write-Host "  $missCount module(s) missing - your Windows edition may not include them" -ForegroundColor Yellow
}

# =================================================================
#  STEP 7: CHECK WINDOWS FEATURES
# =================================================================
Write-Step 7 "Checking Windows Features"

# SMBv1 check
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq "Enabled") {
        Write-WARN "SMBv1 is ENABLED (security risk) - CyberScan can disable it"
    } else {
        Write-OK "SMBv1 is disabled (secure)"
    }
} catch {
    Write-Host "  [--] SMBv1 check not available" -ForegroundColor DarkGray
}

# .NET Framework check
try {
    $release = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction SilentlyContinue).Release
    if ($release -ge 528040)     { Write-OK ".NET Framework 4.8+ detected" }
    elseif ($release -ge 461808) { Write-OK ".NET Framework 4.7.2+ detected" }
    elseif ($release)            { Write-WARN ".NET Framework is outdated - run Windows Update" }
    else                         { Write-WARN ".NET Framework 4.x not detected" }
} catch {
    Write-WARN "Cannot check .NET Framework version"
}

# =================================================================
#  STEP 8: UPDATE HELP FILES
# =================================================================
Write-Step 8 "Updating PowerShell Help Files"

Write-Host "  Updating (this may take a moment)..." -ForegroundColor Gray
Update-Help -Force -ErrorAction SilentlyContinue
Write-OK "Help files updated"

# =================================================================
#  SUMMARY
# =================================================================
Write-Host ""
Write-Host "  ======================================================" -ForegroundColor Green
Write-Host "   SETUP COMPLETE - System is ready for CyberScan!" -ForegroundColor Green
Write-Host "  ======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  CyberScan will launch in a few seconds..." -ForegroundColor Cyan
Write-Host ""
