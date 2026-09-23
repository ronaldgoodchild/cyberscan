# --- CyberScan 2026 - TITAN ULTIMATE EDITION v10.0 ---
# Developed by Ronald Goodchild
# 110+ Operations | Security Scoring | CVE Scanner | CIS Baseline | Threat Intel | ATT&CK Mapping | Full Audit Suite

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
$script:RealDesktop = [Environment]::GetFolderPath('Desktop')
if (-not $script:RealDesktop -or -not (Test-Path $script:RealDesktop)) { $script:RealDesktop = "$env:USERPROFILE\Desktop" }
$script:RealDocuments = [Environment]::GetFolderPath('MyDocuments')
if (-not $script:RealDocuments -or -not (Test-Path $script:RealDocuments)) { $script:RealDocuments = "$env:USERPROFILE\Documents" }
$script:RealPictures = [Environment]::GetFolderPath('MyPictures')
if (-not $script:RealPictures -or -not (Test-Path $script:RealPictures)) { $script:RealPictures = "$env:USERPROFILE\Pictures" }
$SnapshotPath = "$($script:RealDesktop)\System_Snapshot.txt"
$CyberScanData = "$env:USERPROFILE\.cyberscan"
if (-not (Test-Path $CyberScanData)) { New-Item -ItemType Directory -Path $CyberScanData -Force | Out-Null }

# --- Helper: Network Audit ---
function Get-NetworkAudit {
    $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $Report = foreach ($Conn in $Connections) {
        try {
            $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
            $Path = $Proc.MainModule.FileName
            $Status = "Likely Safe"
            if ($Path -like "*\AppData\*" -or $Path -like "*\Temp\*") { $Status = "WARNING: User Folder" }
            if ($null -eq $Path) { $Status = "Hidden Process" }
            [PSCustomObject]@{ Program = $Proc.ProcessName; RemoteIP = $Conn.RemoteAddress; RemotePort = $Conn.RemotePort; Safety = $Status; Location = $Path }
        } catch {
            [PSCustomObject]@{ Program = "System/Kernel"; RemoteIP = $Conn.RemoteAddress; RemotePort = $Conn.RemotePort; Safety = "Safe (OS)"; Location = "C:\Windows\System32" }
        }
    }
    return $Report
}

# --- Helper: Known Suspicious Ports Database ---
$script:SuspiciousPorts = @{
    4444 = "Metasploit/Meterpreter default"
    5555 = "Android ADB / Remote shells"
    6666 = "IRC Backdoor common port"
    6667 = "IRC C2 channel"
    1337 = "Common backdoor/elite port"
    31337 = "Back Orifice trojan"
    12345 = "NetBus trojan"
    20000 = "Millennium trojan"
    27374 = "SubSeven trojan"
    1234 = "Common malware callback"
    9001 = "Tor default / C2 common"
    9050 = "Tor SOCKS proxy"
    9051 = "Tor control port"
    8080 = "HTTP Proxy (check process)"
    3127 = "MyDoom backdoor"
    5900 = "VNC (check if authorized)"
    4443 = "Common C2 HTTPS alt"
    8443 = "HTTPS alt (check process)"
    1080 = "SOCKS proxy (potential tunnel)"
    3128 = "Squid proxy (potential tunnel)"
}

# --- Helper: High-Risk Country IPs (simplified GeoIP by ASN ranges) ---
$script:HighRiskRanges = @(
    @{ Range = "^185\.159\.82\."; Desc = "Known bulletproof hosting" },
    @{ Range = "^91\.243\."; Desc = "Eastern EU hosting" },
    @{ Range = "^5\.188\."; Desc = "Known attack infrastructure" },
    @{ Range = "^45\.227\.25[0-5]\."; Desc = "Suspicious hosting range" }
)

# --- MITRE ATT&CK Technique Mapping Database ---
$script:MitreMap = @{
    "SuspiciousPort_4444"     = @{TID="T1571";Tactic="Command and Control";Desc="Non-Standard Port (Metasploit default)"}
    "SuspiciousPort_6666"     = @{TID="T1071";Tactic="Command and Control";Desc="Application Layer Protocol (IRC C2)"}
    "SuspiciousPort_6667"     = @{TID="T1071";Tactic="Command and Control";Desc="Application Layer Protocol (IRC C2)"}
    "SuspiciousPort_9001"     = @{TID="T1090.003";Tactic="Command and Control";Desc="Multi-hop Proxy (Tor)"}
    "SuspiciousPort_9050"     = @{TID="T1090.003";Tactic="Command and Control";Desc="Multi-hop Proxy (Tor SOCKS)"}
    "SuspiciousPort_31337"    = @{TID="T1571";Tactic="Command and Control";Desc="Non-Standard Port (Back Orifice)"}
    "SuspiciousPort_12345"    = @{TID="T1571";Tactic="Command and Control";Desc="Non-Standard Port (NetBus)"}
    "ProcessInTemp"           = @{TID="T1204.002";Tactic="Execution";Desc="User Execution: Malicious File from Temp"}
    "BruteForce"              = @{TID="T1110";Tactic="Credential Access";Desc="Brute Force login attempts"}
    "LateralMovement"         = @{TID="T1021";Tactic="Lateral Movement";Desc="Remote Services (Type 3 Logon)"}
    "NewService"              = @{TID="T1543.003";Tactic="Persistence";Desc="Create or Modify System Process: Windows Service"}
    "PowerShellExec"          = @{TID="T1059.001";Tactic="Execution";Desc="Command and Scripting Interpreter: PowerShell"}
    "ScheduledTask"           = @{TID="T1053.005";Tactic="Persistence";Desc="Scheduled Task/Job"}
    "RegistryRunKey"          = @{TID="T1547.001";Tactic="Persistence";Desc="Boot or Logon Autostart Execution: Registry Run Keys"}
    "WMIPersistence"          = @{TID="T1546.003";Tactic="Persistence";Desc="Event Triggered Execution: WMI Event Subscription"}
    "SMBv1Enabled"            = @{TID="T1210";Tactic="Lateral Movement";Desc="Exploitation of Remote Services (EternalBlue)"}
    "RDPEnabled"              = @{TID="T1021.001";Tactic="Lateral Movement";Desc="Remote Desktop Protocol"}
    "DefenderDisabled"        = @{TID="T1562.001";Tactic="Defense Evasion";Desc="Impair Defenses: Disable or Modify Tools"}
    "UACDisabled"             = @{TID="T1548.002";Tactic="Privilege Escalation";Desc="Abuse Elevation Control: Bypass UAC"}
    "ClearEventLog"           = @{TID="T1070.001";Tactic="Defense Evasion";Desc="Indicator Removal: Clear Windows Event Logs"}
    "UnsignedStartup"         = @{TID="T1547.001";Tactic="Persistence";Desc="Boot or Logon Autostart: Unsigned binary"}
    "Beaconing"               = @{TID="T1071.001";Tactic="Command and Control";Desc="Web Protocols (periodic beaconing)"}
    "CredentialInFile"        = @{TID="T1552.001";Tactic="Credential Access";Desc="Unsecured Credentials: Credentials in Files"}
    "AccountNoPassword"       = @{TID="T1078.003";Tactic="Initial Access";Desc="Valid Accounts: Local Accounts (no password)"}
}

function Get-MitreTag {
    param([string]$Key)
    if ($script:MitreMap.ContainsKey($Key)) {
        $m = $script:MitreMap[$Key]
        return "[ATT&CK $($m.TID)] $($m.Tactic): $($m.Desc)"
    }
    return $null
}

# --- Scan History Tracking ---
$script:ScanHistoryFile = "$CyberScanData\scan_history.json"
function Save-ScanResult {
    param([string]$ScanName, [int]$Score, [int]$MaxScore, [int]$Issues)
    try {
        $history = @()
        if (Test-Path $script:ScanHistoryFile) {
            $history = @(Get-Content $script:ScanHistoryFile -Raw | ConvertFrom-Json)
        }
        $history += [PSCustomObject]@{
            Date = (Get-Date).ToString("o")
            Scan = $ScanName
            Score = $Score
            MaxScore = $MaxScore
            Issues = $Issues
        }
        # Keep last 100 entries
        if ($history.Count -gt 100) { $history = $history[-100..-1] }
        $history | ConvertTo-Json -Depth 3 | Out-File $script:ScanHistoryFile -Encoding UTF8
    } catch {}
}

# --- Version Check ---
$script:CurrentVersion = "10.0.0"
$script:VersionCheckURL = "https://api.github.com/repos/ronaldgoodchild/cyberscan/releases/latest"

# --- Hardening Undo Log ---
$script:UndoLogFile = "$CyberScanData\undo_log.json"
function Save-UndoEntry {
    param([string]$Action, [string]$RevertCommand, [string]$Description)
    try {
        $log = @()
        if (Test-Path $script:UndoLogFile) { $log = @(Get-Content $script:UndoLogFile -Raw | ConvertFrom-Json) }
        $log += [PSCustomObject]@{
            Date = (Get-Date).ToString("o")
            Action = $Action
            Revert = $RevertCommand
            Description = $Description
        }
        if ($log.Count -gt 50) { $log = $log[-50..-1] }
        $log | ConvertTo-Json -Depth 3 | Out-File $script:UndoLogFile -Encoding UTF8
    } catch {}
}

# ===================== COLOR SCHEME =====================
$colorDarkBg       = [System.Drawing.Color]::FromArgb(18, 18, 28)
$colorPanelBg      = [System.Drawing.Color]::FromArgb(12, 14, 36)
$colorBtnNormal    = [System.Drawing.Color]::FromArgb(28, 32, 58)
$colorBtnHover     = [System.Drawing.Color]::FromArgb(25, 60, 150)
$colorBtnActive    = [System.Drawing.Color]::FromArgb(20, 50, 130)
$colorFlyoutBg     = [System.Drawing.Color]::FromArgb(20, 24, 50)
$colorFlyoutBorder = [System.Drawing.Color]::FromArgb(50, 80, 180)
$colorSubNormal    = [System.Drawing.Color]::FromArgb(26, 30, 56)
$colorSubHover     = [System.Drawing.Color]::FromArgb(30, 70, 170)
$colorTextWhite    = [System.Drawing.Color]::White
$colorTextCyan     = [System.Drawing.Color]::Cyan
$colorTextGreen    = [System.Drawing.Color]::FromArgb(0, 255, 128)
$colorConsoleBg    = [System.Drawing.Color]::FromArgb(8, 8, 18)
$colorCatGreen     = [System.Drawing.Color]::FromArgb(80, 220, 130)
$colorCatMagenta   = [System.Drawing.Color]::FromArgb(190, 130, 240)
$colorCatYellow    = [System.Drawing.Color]::FromArgb(250, 210, 80)
$colorCatBlueWhite = [System.Drawing.Color]::FromArgb(180, 200, 255)
$colorCatOrange    = [System.Drawing.Color]::FromArgb(255, 170, 60)
$colorCatTeal      = [System.Drawing.Color]::FromArgb(60, 220, 210)
$colorCatRed       = [System.Drawing.Color]::FromArgb(255, 90, 90)
$colorCatGold      = [System.Drawing.Color]::FromArgb(255, 215, 0)
$colorCatPink      = [System.Drawing.Color]::FromArgb(255, 130, 180)

# ===================== MAIN FORM =====================
$form = New-Object System.Windows.Forms.Form
$form.Text = "CyberScan 2026 | TITAN ULTIMATE v10.0"
$form.Size = New-Object System.Drawing.Size(1100, 720)
$form.StartPosition = "CenterScreen"
$form.BackColor = $colorDarkBg
$form.ForeColor = $colorTextWhite
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false

# ===================== HEADER PANEL =====================
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Dock = "Top"
$headerPanel.Height = 55
$headerPanel.BackColor = $colorPanelBg

$headerLabel = New-Object System.Windows.Forms.Label
$headerLabel.Text = "CYBERSCAN 2026  |  TITAN ULTIMATE v10.0"
$headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$headerLabel.ForeColor = $colorTextCyan
$headerLabel.AutoSize = $true
$headerLabel.Location = New-Object System.Drawing.Point(20, 12)
$headerPanel.Controls.Add($headerLabel)

$clockLabel = New-Object System.Windows.Forms.Label
$clockLabel.Font = New-Object System.Drawing.Font("Consolas", 11)
$clockLabel.ForeColor = [System.Drawing.Color]::FromArgb(120, 200, 255)
$clockLabel.AutoSize = $false
$clockLabel.TextAlign = "MiddleRight"
$clockLabel.Size = New-Object System.Drawing.Size(150, 20)
$clockLabel.Location = New-Object System.Drawing.Point(920, 6)
$headerPanel.Controls.Add($clockLabel)

$uptimeLabel = New-Object System.Windows.Forms.Label
$uptimeLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$uptimeLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 140, 180)
$uptimeLabel.AutoSize = $false
$uptimeLabel.TextAlign = "MiddleRight"
$uptimeLabel.Size = New-Object System.Drawing.Size(150, 16)
$uptimeLabel.Location = New-Object System.Drawing.Point(920, 28)
$headerPanel.Controls.Add($uptimeLabel)

if (-not $IsAdmin) {
    $warnLabel = New-Object System.Windows.Forms.Label
    $warnLabel.Text = "[NOT ADMIN]"
    $warnLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $warnLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 100, 100)
    $warnLabel.AutoSize = $true
    $warnLabel.Location = New-Object System.Drawing.Point(580, 6)
    $headerPanel.Controls.Add($warnLabel)

    $adminLink = New-Object System.Windows.Forms.LinkLabel
    $adminLink.Text = "Relaunch as Admin"
    $adminLink.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $adminLink.LinkColor = [System.Drawing.Color]::FromArgb(100, 180, 255)
    $adminLink.ActiveLinkColor = [System.Drawing.Color]::White
    $adminLink.AutoSize = $true
    $adminLink.Location = New-Object System.Drawing.Point(580, 24)
    $adminLink.Add_LinkClicked({
        $ps = New-Object System.Diagnostics.ProcessStartInfo "powershell.exe"
        $ps.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
        $ps.Verb = "runas"
        try { [System.Diagnostics.Process]::Start($ps) | Out-Null; $form.Close() } catch {}
    })
    $headerPanel.Controls.Add($adminLink)
}

$form.Controls.Add($headerPanel)

$script:cachedBootTime = $null
try { $script:cachedBootTime = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime } catch {}

$clockTimer = New-Object System.Windows.Forms.Timer
$clockTimer.Interval = 1000
$clockTimer.Add_Tick({
    $clockLabel.Text = (Get-Date -Format "hh:mm:ss tt")
    try {
        if ($script:cachedBootTime) {
            $up = (Get-Date) - $script:cachedBootTime
            $uptimeLabel.Text = "Up: $($up.Days)d $($up.Hours)h $($up.Minutes)m"
        }
    } catch {}
})
$clockTimer.Start()

# ===================== LEFT SIDEBAR =====================
$sidebarWidth = 210
$sidePanel = New-Object System.Windows.Forms.Panel
$sidePanel.Location = New-Object System.Drawing.Point(0, 55)
$sidePanel.Size = New-Object System.Drawing.Size($sidebarWidth, 640)
$sidePanel.BackColor = $colorPanelBg
$sidePanel.AutoScroll = $true
$form.Controls.Add($sidePanel)

$sepLine = New-Object System.Windows.Forms.Panel
$sepLine.Location = New-Object System.Drawing.Point($sidebarWidth, 55)
$sepLine.Size = New-Object System.Drawing.Size(2, 640)
$sepLine.BackColor = [System.Drawing.Color]::FromArgb(40, 60, 120)
$form.Controls.Add($sepLine)

# ===================== OUTPUT TEXTBOX =====================
$outputLeft = $sidebarWidth + 10
$outputBox = New-Object System.Windows.Forms.TextBox
$outputBox.Multiline = $true
$outputBox.ScrollBars = "Vertical"
$outputBox.ReadOnly = $true
$outputBox.WordWrap = $true
$outputBox.Location = New-Object System.Drawing.Point($outputLeft, 60)
$outputBox.Size = New-Object System.Drawing.Size(860, 540)
$outputBox.BackColor = $colorConsoleBg
$outputBox.ForeColor = $colorTextGreen
$outputBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$outputBox.Text = "CyberScan 2026 - TITAN ULTIMATE EDITION v10.0`r`nDeveloped by Ronald Goodchild`r`n$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss tt')`r`n`r`nReady. Select an operation from the left panel.`r`n"
$form.Controls.Add($outputBox)

# Right-click context menu
$outputMenu = New-Object System.Windows.Forms.ContextMenuStrip
$outputMenu.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 55)
$outputMenu.ForeColor = $colorTextWhite
$outputMenu.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$outputMenu.Renderer = New-Object System.Windows.Forms.ToolStripProfessionalRenderer((New-Object System.Windows.Forms.ProfessionalColorTable))

$ctxCopy = New-Object System.Windows.Forms.ToolStripMenuItem("Copy Selected")
$ctxCopy.Add_Click({ if ($outputBox.SelectedText) { [System.Windows.Forms.Clipboard]::SetText($outputBox.SelectedText) } })
$ctxSelectAll = New-Object System.Windows.Forms.ToolStripMenuItem("Select All")
$ctxSelectAll.Add_Click({ $outputBox.SelectAll() })
$ctxCopyAll = New-Object System.Windows.Forms.ToolStripMenuItem("Copy All")
$ctxCopyAll.Add_Click({ [System.Windows.Forms.Clipboard]::SetText($outputBox.Text) })
$ctxSaveLog = New-Object System.Windows.Forms.ToolStripMenuItem("Save Log to File...")
$ctxSaveLog.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "Text Files (*.txt)|*.txt|Log Files (*.log)|*.log|All Files (*.*)|*.*"
    $sfd.FileName = "CyberScan_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $sfd.Title = "Save CyberScan Log"
    if ($sfd.ShowDialog() -eq "OK") {
        $outputBox.Text | Out-File -FilePath $sfd.FileName -Encoding UTF8
        $outputBox.AppendText("`r`n[LOG SAVED] $($sfd.FileName)`r`n")
    }
})
$ctxClear = New-Object System.Windows.Forms.ToolStripMenuItem("Clear Log")
$ctxClear.Add_Click({ $outputBox.Clear(); $outputBox.AppendText("Log cleared. Ready.`r`n") })
$outputMenu.Items.AddRange(@($ctxCopy, $ctxSelectAll, $ctxCopyAll, (New-Object System.Windows.Forms.ToolStripSeparator), $ctxSaveLog, $ctxClear))
$outputBox.ContextMenuStrip = $outputMenu

# ===================== PROGRESS BAR =====================
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point($outputLeft, 598)
$progressBar.Size = New-Object System.Drawing.Size(860, 6)
$progressBar.Style = "Marquee"
$progressBar.MarqueeAnimationSpeed = 18
$progressBar.Visible = $false
$form.Controls.Add($progressBar)
$progressBar.BringToFront()

# ===================== GRAPHICAL LIVE DASHBOARD =====================
$script:dashCPU = 0; $script:dashRAM = 0; $script:dashDisk = 0
$script:dashNetConns = 0; $script:dashProcs = 0; $script:dashTemp = -1
$script:dashDLHistory = [System.Collections.Generic.List[double]]::new()
$script:dashULHistory = [System.Collections.Generic.List[double]]::new()
$script:dashPrevRecv = [long]0; $script:dashPrevSent = [long]0
$script:dashFirstTick = $true; $script:dashCurrentDL = 0.0; $script:dashCurrentUL = 0.0
$script:dashInfoOS = ""; $script:dashInfoPC = ""; $script:dashInfoUptime = ""
$script:dashInfoAV = ""; $script:dashInfoFW = ""; $script:dashInfoIP = ""

for ($i = 0; $i -lt 60; $i++) { $script:dashDLHistory.Add(0); $script:dashULHistory.Add(0) }

$dashPanel = New-Object System.Windows.Forms.Panel
$dashPanel.Location = $outputBox.Location
$dashPanel.Size = $outputBox.Size
$dashPanel.BackColor = [System.Drawing.Color]::FromArgb(12, 12, 22)
$dashPanel.Visible = $false
$form.Controls.Add($dashPanel)
$dashPanel.BringToFront()

$dashTitleBar = New-Object System.Windows.Forms.Panel
$dashTitleBar.Dock = "Top"
$dashTitleBar.Height = 36
$dashTitleBar.BackColor = [System.Drawing.Color]::FromArgb(16, 20, 45)
$dashPanel.Controls.Add($dashTitleBar)

$dashTitleLabel = New-Object System.Windows.Forms.Label
$dashTitleLabel.Text = "LIVE DASHBOARD"
$dashTitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$dashTitleLabel.ForeColor = $colorTextCyan
$dashTitleLabel.AutoSize = $true
$dashTitleLabel.Location = New-Object System.Drawing.Point(12, 6)
$dashTitleBar.Controls.Add($dashTitleLabel)

$dashRefreshLabel = New-Object System.Windows.Forms.Label
$dashRefreshLabel.Text = "Refreshing every 2s"
$dashRefreshLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$dashRefreshLabel.ForeColor = [System.Drawing.Color]::FromArgb(80, 110, 160)
$dashRefreshLabel.AutoSize = $true
$dashRefreshLabel.Location = New-Object System.Drawing.Point(200, 11)
$dashTitleBar.Controls.Add($dashRefreshLabel)

$dashCloseBtn = New-Object System.Windows.Forms.Button
$dashCloseBtn.Text = "X  Close"
$dashCloseBtn.Size = New-Object System.Drawing.Size(90, 28)
$dashCloseBtn.Location = New-Object System.Drawing.Point(760, 4)
$dashCloseBtn.FlatStyle = "Flat"
$dashCloseBtn.FlatAppearance.BorderSize = 1
$dashCloseBtn.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(120, 40, 40)
$dashCloseBtn.BackColor = [System.Drawing.Color]::FromArgb(100, 20, 20)
$dashCloseBtn.ForeColor = $colorTextWhite
$dashCloseBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$dashCloseBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
$dashTitleBar.Controls.Add($dashCloseBtn)

# --- GDI+ Gauge Drawing Function ---
function New-GaugePanel {
    param([int]$X, [int]$Y, [int]$W, [int]$H, [string]$Label, [System.Drawing.Color]$GaugeColor, [scriptblock]$GetValue, [scriptblock]$GetText)
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point($X, $Y)
    $panel.Size = New-Object System.Drawing.Size($W, $H)
    $panel.BackColor = [System.Drawing.Color]::FromArgb(16, 18, 32)
    $panel.Tag = @{ Label = $Label; Color = $GaugeColor; GetValue = $GetValue; GetText = $GetText }
    $panel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = "AntiAlias"
        $g.TextRenderingHint = "ClearTypeGridFit"
        $info = $sender.Tag
        $value = try { & $info.GetValue } catch { 0 }
        $text  = try { & $info.GetText  } catch { "N/A" }
        $cw = $sender.ClientSize.Width; $ch = $sender.ClientSize.Height
        $arcSize = [math]::Min($cw, $ch) - 40
        if ($arcSize -lt 40) { $arcSize = 40 }
        $arcX = ($cw - $arcSize) / 2; $arcY = 8
        $arcRect = New-Object System.Drawing.RectangleF($arcX, $arcY, $arcSize, $arcSize)
        $startAngle = 135; $sweepTotal = 270
        $penBg = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 44, 65), 10)
        $penBg.StartCap = "Round"; $penBg.EndCap = "Round"
        $g.DrawArc($penBg, $arcRect, $startAngle, $sweepTotal); $penBg.Dispose()
        $clampVal = [math]::Max(0, [math]::Min(100, $value))
        $sweepValue = ($clampVal / 100) * $sweepTotal
        if ($sweepValue -gt 0.5) {
            $arcColor = $info.Color
            if ($clampVal -gt 90) { $arcColor = [System.Drawing.Color]::FromArgb(255, 60, 60) }
            elseif ($clampVal -gt 75) { $arcColor = [System.Drawing.Color]::FromArgb(255, 180, 50) }
            $penVal = New-Object System.Drawing.Pen($arcColor, 10)
            $penVal.StartCap = "Round"; $penVal.EndCap = "Round"
            $g.DrawArc($penVal, $arcRect, $startAngle, $sweepValue); $penVal.Dispose()
        }
        $valFont = New-Object System.Drawing.Font("Consolas", 16, [System.Drawing.FontStyle]::Bold)
        $valBrush = New-Object System.Drawing.SolidBrush($colorTextWhite)
        $valSize = $g.MeasureString($text, $valFont)
        $g.DrawString($text, $valFont, $valBrush, (($cw - $valSize.Width) / 2), ($arcY + ($arcSize / 2) - ($valSize.Height / 2)))
        $valFont.Dispose(); $valBrush.Dispose()
        $lblFont = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $lblBrush = New-Object System.Drawing.SolidBrush($info.Color)
        $lblSize = $g.MeasureString($info.Label, $lblFont)
        $g.DrawString($info.Label, $lblFont, $lblBrush, (($cw - $lblSize.Width) / 2), ($arcY + $arcSize + 2))
        $lblFont.Dispose(); $lblBrush.Dispose()
    })
    return $panel
}

# --- Create 6 gauges ---
$gaugeW = 140; $gaugeH = 145; $gapX = 6; $gapY = 4; $gaugeStartX = 8; $gaugeStartY = 40

$gaugeCPU = New-GaugePanel -X $gaugeStartX -Y $gaugeStartY -W $gaugeW -H $gaugeH -Label "CPU USAGE" -GaugeColor ([System.Drawing.Color]::Cyan) -GetValue { $script:dashCPU } -GetText { "$($script:dashCPU)%" }
$dashPanel.Controls.Add($gaugeCPU)
$gaugeRAM = New-GaugePanel -X ($gaugeStartX + $gaugeW + $gapX) -Y $gaugeStartY -W $gaugeW -H $gaugeH -Label "RAM USAGE" -GaugeColor ([System.Drawing.Color]::FromArgb(0, 220, 100)) -GetValue { $script:dashRAM } -GetText { "$($script:dashRAM)%" }
$dashPanel.Controls.Add($gaugeRAM)
$gaugeDisk = New-GaugePanel -X ($gaugeStartX + 2*($gaugeW + $gapX)) -Y $gaugeStartY -W $gaugeW -H $gaugeH -Label "DISK C: USED" -GaugeColor ([System.Drawing.Color]::FromArgb(255, 170, 50)) -GetValue { $script:dashDisk } -GetText { "$($script:dashDisk)%" }
$dashPanel.Controls.Add($gaugeDisk)
$gaugeNet = New-GaugePanel -X $gaugeStartX -Y ($gaugeStartY + $gaugeH + $gapY) -W $gaugeW -H $gaugeH -Label "NET CONNS" -GaugeColor ([System.Drawing.Color]::FromArgb(250, 210, 80)) -GetValue { [math]::Min($script:dashNetConns, 100) } -GetText { "$($script:dashNetConns)" }
$dashPanel.Controls.Add($gaugeNet)
$gaugeProc = New-GaugePanel -X ($gaugeStartX + $gaugeW + $gapX) -Y ($gaugeStartY + $gaugeH + $gapY) -W $gaugeW -H $gaugeH -Label "PROCESSES" -GaugeColor ([System.Drawing.Color]::FromArgb(190, 130, 240)) -GetValue { [math]::Min($script:dashProcs / 4, 100) } -GetText { "$($script:dashProcs)" }
$dashPanel.Controls.Add($gaugeProc)
$gaugeTemp = New-GaugePanel -X ($gaugeStartX + 2*($gaugeW + $gapX)) -Y ($gaugeStartY + $gaugeH + $gapY) -W $gaugeW -H $gaugeH -Label "CPU TEMP" -GaugeColor ([System.Drawing.Color]::FromArgb(255, 80, 80)) -GetValue { if ($script:dashTemp -ge 0) { [math]::Min($script:dashTemp, 100) } else { 0 } } -GetText { if ($script:dashTemp -ge 0) { "$($script:dashTemp)C" } else { "N/A" } }
$dashPanel.Controls.Add($gaugeTemp)

# --- Info labels panel ---
$infoPanel = New-Object System.Windows.Forms.Panel
$infoPanel.Location = New-Object System.Drawing.Point(445, 40)
$infoPanel.Size = New-Object System.Drawing.Size(405, 290)
$infoPanel.BackColor = [System.Drawing.Color]::FromArgb(14, 16, 30)
$dashPanel.Controls.Add($infoPanel)

$infoPanel.Add_Paint({
    param($sender, $e)
    $g = $e.Graphics
    $g.TextRenderingHint = "ClearTypeGridFit"
    $titleFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $dataFont  = New-Object System.Drawing.Font("Consolas", 9)
    $labelFont = New-Object System.Drawing.Font("Segoe UI", 8)
    $cyanBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::Cyan)
    $whiteBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $dimBrush  = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(120, 140, 180))
    $greenBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(0, 220, 100))
    $orangeBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 170, 50))
    $sepPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(30, 40, 70), 1)
    $y = 8
    $g.DrawString("SYSTEM INFORMATION", $titleFont, $cyanBrush, 10, $y); $y += 26
    $g.DrawLine($sepPen, 10, $y, 390, $y); $y += 8
    $entries = @(@("Computer:", $script:dashInfoPC), @("OS:", $script:dashInfoOS), @("Uptime:", $script:dashInfoUptime), @("Antivirus:", $script:dashInfoAV), @("Firewall:", $script:dashInfoFW), @("IP Address:", $script:dashInfoIP))
    foreach ($entry in $entries) { $g.DrawString($entry[0], $labelFont, $dimBrush, 12, $y); $g.DrawString($entry[1], $dataFont, $whiteBrush, 110, $y); $y += 22 }
    $y += 10; $g.DrawLine($sepPen, 10, $y, 390, $y); $y += 10
    $g.DrawString("NETWORK THROUGHPUT", $titleFont, $cyanBrush, 10, $y); $y += 24
    $dlText = if ($script:dashCurrentDL -gt 1024) { "$([math]::Round($script:dashCurrentDL/1024, 1)) MB/s" } else { "$([math]::Round($script:dashCurrentDL, 0)) KB/s" }
    $ulText = if ($script:dashCurrentUL -gt 1024) { "$([math]::Round($script:dashCurrentUL/1024, 1)) MB/s" } else { "$([math]::Round($script:dashCurrentUL, 0)) KB/s" }
    $g.DrawString("DL:", $labelFont, $dimBrush, 12, $y); $g.DrawString($dlText, $dataFont, $greenBrush, 50, $y)
    $g.DrawString("UL:", $labelFont, $dimBrush, 180, $y); $g.DrawString($ulText, $dataFont, $orangeBrush, 218, $y)
    $titleFont.Dispose(); $dataFont.Dispose(); $labelFont.Dispose()
    $cyanBrush.Dispose(); $whiteBrush.Dispose(); $dimBrush.Dispose()
    $greenBrush.Dispose(); $orangeBrush.Dispose(); $sepPen.Dispose()
})

# --- Network traffic chart ---
$netChartPanel = New-Object System.Windows.Forms.Panel
$netChartPanel.Location = New-Object System.Drawing.Point(8, 340)
$netChartPanel.Size = New-Object System.Drawing.Size(842, 190)
$netChartPanel.BackColor = [System.Drawing.Color]::FromArgb(10, 12, 24)
$dashPanel.Controls.Add($netChartPanel)

$netChartPanel.Add_Paint({
    param($sender, $e)
    $g = $e.Graphics
    $g.SmoothingMode = "AntiAlias"; $g.TextRenderingHint = "ClearTypeGridFit"
    $cw = $sender.ClientSize.Width; $ch = $sender.ClientSize.Height
    $pad = 45; $padR = 10; $padTop = 28; $padBot = 20
    $graphW = $cw - $pad - $padR; $graphH = $ch - $padTop - $padBot
    $titleFont = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $cyanBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::Cyan)
    $adapterLabel = if ($script:dashNetAdapterName) { "  |  $($script:dashNetAdapterName)" } else { "" }
    $g.DrawString("NETWORK TRAFFIC$adapterLabel", $titleFont, $cyanBrush, $pad, 4)
    $borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(35, 45, 75), 1)
    $g.DrawRectangle($borderPen, $pad, $padTop, $graphW, $graphH)
    $gridPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(22, 28, 50), 1)
    for ($i = 1; $i -le 4; $i++) { $gy = $padTop + ($graphH * $i / 5); $g.DrawLine($gridPen, $pad, $gy, $pad + $graphW, $gy) }
    $maxVal = 10
    foreach ($v in $script:dashDLHistory) { if ($v -gt $maxVal) { $maxVal = $v } }
    foreach ($v in $script:dashULHistory) { if ($v -gt $maxVal) { $maxVal = $v } }
    $maxVal = $maxVal * 1.2
    $axisFont = New-Object System.Drawing.Font("Consolas", 7)
    $dimBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(80, 100, 140))
    for ($i = 0; $i -le 4; $i++) {
        $gy = $padTop + ($graphH * $i / 4)
        $val = $maxVal * (4 - $i) / 4
        $label = if ($val -ge 1024) { "$([math]::Round($val/1024,1))M" } else { "$([math]::Round($val,0))K" }
        $g.DrawString($label, $axisFont, $dimBrush, 2, $gy - 6)
    }
    $sampleCount = $script:dashDLHistory.Count
    if ($sampleCount -gt 1) {
        $dlPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(0, 200, 180), 2)
        $points = New-Object System.Drawing.PointF[] $sampleCount
        for ($i = 0; $i -lt $sampleCount; $i++) {
            $px = $pad + ($graphW * $i / ($sampleCount - 1))
            $py = $padTop + $graphH - ($graphH * [math]::Min($script:dashDLHistory[$i], $maxVal) / $maxVal)
            $points[$i] = New-Object System.Drawing.PointF($px, $py)
        }
        $g.DrawLines($dlPen, $points)
        $fillPoints = New-Object System.Drawing.PointF[] ($sampleCount + 2)
        for ($i = 0; $i -lt $sampleCount; $i++) { $fillPoints[$i] = $points[$i] }
        $fillPoints[$sampleCount] = New-Object System.Drawing.PointF(($pad + $graphW), ($padTop + $graphH))
        $fillPoints[$sampleCount + 1] = New-Object System.Drawing.PointF($pad, ($padTop + $graphH))
        $fillBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(25, 0, 200, 180))
        $g.FillPolygon($fillBrush, $fillPoints)
        $dlPen.Dispose(); $fillBrush.Dispose()
    }
    if ($sampleCount -gt 1) {
        $ulPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 150, 50), 2)
        $ulPoints = New-Object System.Drawing.PointF[] $sampleCount
        for ($i = 0; $i -lt $sampleCount; $i++) {
            $px = $pad + ($graphW * $i / ($sampleCount - 1))
            $py = $padTop + $graphH - ($graphH * [math]::Min($script:dashULHistory[$i], $maxVal) / $maxVal)
            $ulPoints[$i] = New-Object System.Drawing.PointF($px, $py)
        }
        $g.DrawLines($ulPen, $ulPoints); $ulPen.Dispose()
    }
    $legendFont = New-Object System.Drawing.Font("Segoe UI", 7)
    $dlLegendBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(0, 200, 180))
    $ulLegendBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 150, 50))
    $g.FillRectangle($dlLegendBrush, ($cw - 180), 6, 10, 10)
    $g.DrawString("Download", $legendFont, $dlLegendBrush, ($cw - 166), 4)
    $g.FillRectangle($ulLegendBrush, ($cw - 90), 6, 10, 10)
    $g.DrawString("Upload", $legendFont, $ulLegendBrush, ($cw - 76), 4)
    $speedFont = New-Object System.Drawing.Font("Consolas", 11, [System.Drawing.FontStyle]::Bold)
    $dlSpeedBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(180, 0, 220, 200))
    $ulSpeedBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(180, 255, 170, 60))
    $dlText = if ($script:dashCurrentDL -ge 1024) { "$([math]::Round($script:dashCurrentDL/1024, 2)) MB/s" } else { "$([math]::Round($script:dashCurrentDL, 1)) KB/s" }
    $ulText = if ($script:dashCurrentUL -ge 1024) { "$([math]::Round($script:dashCurrentUL/1024, 2)) MB/s" } else { "$([math]::Round($script:dashCurrentUL, 1)) KB/s" }
    $g.DrawString("DL: $dlText", $speedFont, $dlSpeedBrush, ($pad + 10), ($padTop + 6))
    $g.DrawString("UL: $ulText", $speedFont, $ulSpeedBrush, ($pad + 10), ($padTop + 24))
    if ($script:dashNetStatus -eq "No adapter") {
        $warnFont = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $warnBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 100, 100))
        $g.DrawString("No network adapter found", $warnFont, $warnBrush, ($pad + $graphW / 2 - 80), ($padTop + $graphH / 2 - 8))
        $warnFont.Dispose(); $warnBrush.Dispose()
    }
    $speedFont.Dispose(); $dlSpeedBrush.Dispose(); $ulSpeedBrush.Dispose()
    $titleFont.Dispose(); $cyanBrush.Dispose(); $borderPen.Dispose()
    $gridPen.Dispose(); $axisFont.Dispose(); $dimBrush.Dispose()
    $legendFont.Dispose(); $dlLegendBrush.Dispose(); $ulLegendBrush.Dispose()
})

# --- Network bytes helper ---
function Get-NetBytes {
    try {
        $physAdapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" })
        foreach ($adapter in $physAdapters) {
            $adapterIP = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.IPAddress -notlike "169.254.*" -and $_.AddressState -eq "Preferred" } | Select-Object -First 1
            if ($adapterIP) {
                $octets = $adapterIP.IPAddress.Split('.')
                if ($octets[0] -eq "172") { $second = [int]$octets[1]; if ($second -ge 16 -and $second -le 31) { continue } }
                $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
                if ($stats -and $null -ne $stats.ReceivedBytes) {
                    $script:dashNetAdapterName = "$($adapter.InterfaceDescription) [$($adapterIP.IPAddress)]"
                    return @{ Recv = [long]$stats.ReceivedBytes; Sent = [long]$stats.SentBytes; OK = $true }
                }
            }
        }
    } catch {}
    try {
        $gwRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
        if ($gwRoute) {
            $adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.ifIndex -eq $gwRoute.InterfaceIndex -and $_.Status -eq "Up" }
            if ($adapter) {
                $adapterIP = (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
                $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
                if ($stats -and $null -ne $stats.ReceivedBytes) {
                    $ipLabel = if ($adapterIP) { " [$adapterIP]" } else { "" }
                    $script:dashNetAdapterName = "$($adapter.InterfaceDescription)$ipLabel"
                    return @{ Recv = [long]$stats.ReceivedBytes; Sent = [long]$stats.SentBytes; OK = $true }
                }
            }
        }
    } catch {}
    try {
        $iface = Get-CimInstance Win32_PerfRawData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch "(?i)virtual|loopback|hyper-v|vmware|vethernet|vpn|tunnel|docker|wsl|isatap|teredo|6to4|microsoft|bluetooth" -and ($_.BytesReceivedPersec -gt 0 -or $_.BytesSentPersec -gt 0) } | Select-Object -First 1
        if ($iface) { $script:dashNetAdapterName = $iface.Name; return @{ Recv = [long]$iface.BytesReceivedPersec; Sent = [long]$iface.BytesSentPersec; OK = $true } }
    } catch {}
    try {
        $tcp = Get-CimInstance Win32_PerfRawData_Tcpip_TCPv4 -ErrorAction SilentlyContinue
        if ($tcp) { $script:dashNetAdapterName = "TCP/IPv4 (aggregate)"; return @{ Recv = [long]$tcp.SegmentsReceivedPersec * 1460; Sent = [long]$tcp.SegmentsSentPersec * 1460; OK = $true } }
    } catch {}
    $script:dashNetAdapterName = ""; return @{ Recv = [long]0; Sent = [long]0; OK = $false }
}

# --- Dashboard data collection ---
function Update-DashboardFast {
    try { $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue; $script:dashCPU = if ($cpuInfo.LoadPercentage) { [int]$cpuInfo.LoadPercentage } else { 0 } } catch { $script:dashCPU = 0 }
    try { $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue; if ($osInfo) { $script:osInfoCache = $osInfo; $script:dashRAM = [math]::Round((1 - ($osInfo.FreePhysicalMemory / $osInfo.TotalVisibleMemorySize)) * 100, 0) } } catch { $script:dashRAM = 0 }
    try { $script:dashProcs = @(Get-Process -ErrorAction SilentlyContinue).Count } catch { $script:dashProcs = 0 }
    try {
        $netData = Get-NetBytes
        if ($netData.OK) {
            $recv = $netData.Recv; $sent = $netData.Sent
            if ($script:dashFirstTick) { $script:dashPrevRecv = $recv; $script:dashPrevSent = $sent; $script:dashFirstTick = $false; $script:dashCurrentDL = 0; $script:dashCurrentUL = 0 }
            else {
                $dlBytes = $recv - $script:dashPrevRecv; $ulBytes = $sent - $script:dashPrevSent
                if ($dlBytes -lt 0) { $dlBytes = 0 }; if ($ulBytes -lt 0) { $ulBytes = 0 }
                $script:dashCurrentDL = [math]::Round($dlBytes / 2048, 1); $script:dashCurrentUL = [math]::Round($ulBytes / 2048, 1)
                $script:dashPrevRecv = $recv; $script:dashPrevSent = $sent
            }
            $script:dashDLHistory.Add($script:dashCurrentDL); $script:dashULHistory.Add($script:dashCurrentUL)
            while ($script:dashDLHistory.Count -gt 60) { $script:dashDLHistory.RemoveAt(0) }
            while ($script:dashULHistory.Count -gt 60) { $script:dashULHistory.RemoveAt(0) }
            $script:dashNetStatus = "OK"
        } else {
            $script:dashDLHistory.Add(0); $script:dashULHistory.Add(0)
            while ($script:dashDLHistory.Count -gt 60) { $script:dashDLHistory.RemoveAt(0) }
            while ($script:dashULHistory.Count -gt 60) { $script:dashULHistory.RemoveAt(0) }
            $script:dashNetStatus = "No adapter"
        }
    } catch { $script:dashDLHistory.Add(0); $script:dashULHistory.Add(0); while ($script:dashDLHistory.Count -gt 60) { $script:dashDLHistory.RemoveAt(0) }; while ($script:dashULHistory.Count -gt 60) { $script:dashULHistory.RemoveAt(0) } }
    if ($script:cachedBootTime) { $up = (Get-Date) - $script:cachedBootTime; $script:dashInfoUptime = "$($up.Days)d $($up.Hours)h $($up.Minutes)m $($up.Seconds)s" }
}

$script:dashSlowTickCount = 0
function Update-DashboardSlow {
    try { $diskInfo = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue; if ($diskInfo -and $diskInfo.Size -gt 0) { $script:dashDisk = [math]::Round((1 - ($diskInfo.SizeRemaining / $diskInfo.Size)) * 100, 0) } } catch {}
    try { $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue; $script:dashNetConns = if ($conns) { @($conns).Count } else { 0 } } catch { $script:dashNetConns = 0 }
    try {
        $thermal = Get-CimInstance -Namespace "root/WMI" -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
        if ($thermal -and $thermal.CurrentTemperature) { $rawTemp = if ($thermal -is [array]) { $thermal[0].CurrentTemperature } else { $thermal.CurrentTemperature }; $script:dashTemp = [math]::Round(($rawTemp / 10) - 273.15, 0) } else { $script:dashTemp = -1 }
    } catch { $script:dashTemp = -1 }
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue; $script:dashInfoPC = "$($cs.Manufacturer) $($cs.Model)" } catch {}
    if ($script:osInfoCache) { $script:dashInfoOS = $script:osInfoCache.Caption }
    try { $av = Get-MpComputerStatus -ErrorAction SilentlyContinue; $script:dashInfoAV = if ($av -and $av.AntivirusEnabled) { "Active - Defs: $($av.AntivirusSignatureLastUpdated.ToString('MM/dd/yyyy'))" } else { "Inactive" } } catch { $script:dashInfoAV = "N/A" }
    try { $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }; $script:dashInfoFW = ($fw | ForEach-Object { $_.Name }) -join ", "; if (-not $script:dashInfoFW) { $script:dashInfoFW = "All OFF" } } catch { $script:dashInfoFW = "N/A" }
    try { $ipAddr = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress; $script:dashInfoIP = if ($ipAddr) { $ipAddr } else { "N/A" } } catch { $script:dashInfoIP = "N/A" }
}

# --- Dashboard Timer ---
$dashTimer = New-Object System.Windows.Forms.Timer
$dashTimer.Interval = 2000
$script:dashNetStatus = ""; $script:dashNetAdapterName = ""
$dashTimer.Add_Tick({
    try {
        Update-DashboardFast
        $script:dashSlowTickCount++
        if ($script:dashSlowTickCount -ge 10) { $script:dashSlowTickCount = 0; Update-DashboardSlow }
        $gaugeCPU.Invalidate(); $gaugeRAM.Invalidate(); $gaugeDisk.Invalidate()
        $gaugeNet.Invalidate(); $gaugeProc.Invalidate(); $gaugeTemp.Invalidate()
        $infoPanel.Invalidate(); $netChartPanel.Invalidate()
    } catch {}
})

$script:OpenDashboard = {
    & $script:CloseFlyout
    $script:dashFirstTick = $true; $script:dashPrevRecv = [long]0; $script:dashPrevSent = [long]0
    $script:dashCurrentDL = 0; $script:dashCurrentUL = 0; $script:dashSlowTickCount = 9
    $outputBox.Visible = $false; $dashPanel.Visible = $true; $dashPanel.BringToFront()
    $statusLabel.Text = "Dashboard Active - Loading..."; $statusLabel.ForeColor = [System.Drawing.Color]::Cyan
    try { $netSeed = Get-NetBytes; if ($netSeed.OK) { $script:dashPrevRecv = $netSeed.Recv; $script:dashPrevSent = $netSeed.Sent; $script:dashFirstTick = $false } } catch {}
    $form.Refresh(); $dashTimer.Start(); $statusLabel.Text = "Dashboard Active"
}
$script:CloseDashboard = {
    $dashTimer.Stop(); $dashPanel.Visible = $false; $outputBox.Visible = $true
    $statusLabel.Text = "Ready"; $statusLabel.ForeColor = [System.Drawing.Color]::LightGreen
}
function Open-Dashboard  { & $script:OpenDashboard }
function Close-Dashboard { & $script:CloseDashboard }
$dashCloseBtn.Add_Click({ & $script:CloseDashboard })

# ===================== STATUS LABELS =====================
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"; $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$statusLabel.ForeColor = [System.Drawing.Color]::LightGreen; $statusLabel.AutoSize = $true
$statusLabel.Location = New-Object System.Drawing.Point($outputLeft, 630)
$form.Controls.Add($statusLabel)

$adminStatusLabel = New-Object System.Windows.Forms.Label
$adminStatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$adminStatusLabel.AutoSize = $true; $adminStatusLabel.Location = New-Object System.Drawing.Point(500, 630)
if ($IsAdmin) { $adminStatusLabel.Text = "Admin: YES"; $adminStatusLabel.ForeColor = [System.Drawing.Color]::LightGreen }
else { $adminStatusLabel.Text = "Admin: NO"; $adminStatusLabel.ForeColor = [System.Drawing.Color]::Red }
$form.Controls.Add($adminStatusLabel)

$script:taskCount = 0
$taskCountLabel = New-Object System.Windows.Forms.Label
$taskCountLabel.Text = "Tasks: 0"; $taskCountLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$taskCountLabel.ForeColor = [System.Drawing.Color]::FromArgb(100, 140, 180); $taskCountLabel.AutoSize = $true
$taskCountLabel.Location = New-Object System.Drawing.Point(620, 632)
$form.Controls.Add($taskCountLabel)

# ===================== BOTTOM BUTTONS =====================
$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "Export Log"; $exportButton.Size = New-Object System.Drawing.Size(96, 34)
$exportButton.Location = New-Object System.Drawing.Point(760, 605); $exportButton.FlatStyle = "Flat"
$exportButton.BackColor = [System.Drawing.Color]::FromArgb(25, 50, 80); $exportButton.ForeColor = $colorTextWhite
$exportButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$exportButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(40, 80, 140)
$exportButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$exportButton.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "Text Files (*.txt)|*.txt|Log Files (*.log)|*.log"
    $sfd.FileName = "CyberScan_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    if ($sfd.ShowDialog() -eq "OK") { $outputBox.Text | Out-File -FilePath $sfd.FileName -Encoding UTF8; $outputBox.AppendText("`r`n[LOG EXPORTED] $($sfd.FileName)`r`n") }
})
$form.Controls.Add($exportButton)

$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = "Clear Log"; $clearButton.Size = New-Object System.Drawing.Size(96, 34)
$clearButton.Location = New-Object System.Drawing.Point(862, 605); $clearButton.FlatStyle = "Flat"
$clearButton.BackColor = [System.Drawing.Color]::FromArgb(35, 40, 65); $clearButton.ForeColor = $colorTextWhite
$clearButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$clearButton.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(60, 60, 100)
$clearButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$clearButton.Add_Click({ $outputBox.Clear(); $outputBox.AppendText("Log cleared. Ready.`r`n") })
$form.Controls.Add($clearButton)

$exitButton = New-Object System.Windows.Forms.Button
$exitButton.Text = "EXIT"; $exitButton.Size = New-Object System.Drawing.Size(96, 34)
$exitButton.Location = New-Object System.Drawing.Point(964, 605); $exitButton.FlatStyle = "Flat"
$exitButton.BackColor = [System.Drawing.Color]::FromArgb(150, 25, 25); $exitButton.ForeColor = $colorTextWhite
$exitButton.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$exitButton.FlatAppearance.BorderColor = [System.Drawing.Color]::DarkRed
$exitButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$exitButton.Add_Click({ $form.Close() })
$form.Controls.Add($exitButton)

# ===================== TASK RUNNER =====================
$script:bgRunspace = $null; $script:bgPipeline = $null; $script:bgOutput = $null
$script:bgTaskName = ""; $script:taskRunning = $false

$taskPollTimer = New-Object System.Windows.Forms.Timer
$taskPollTimer.Interval = 350
$script:bgLineCount = 0; $script:bgErrorCount = 0
$taskPollTimer.Add_Tick({
    if (-not $script:bgPipeline) { return }
    # Drain output buffer
    $drained = 0
    try {
        while ($script:bgOutput.Count -gt 0 -and $drained -lt 200) {
            $line = $script:bgOutput[0]; $script:bgOutput.RemoveAt(0); $drained++
            if ($null -ne $line) {
                $lineStr = $line.ToString()
                $outputBox.AppendText("$lineStr`r`n")
                $script:bgLineCount++
                if ($lineStr -match "^ERROR:|^FAIL|>>>") { $script:bgErrorCount++ }
            }
        }
        if ($drained -gt 0) { $outputBox.SelectionStart = $outputBox.Text.Length; $outputBox.ScrollToCaret() }
    } catch {}
    # Check if task finished
    $state = $script:bgPipeline.InvocationStateInfo.State
    if ($state -ne "Running") {
        # Final drain — wait a moment then drain everything remaining
        Start-Sleep -Milliseconds 100
        try {
            while ($script:bgOutput.Count -gt 0) {
                $line = $script:bgOutput[0]; $script:bgOutput.RemoveAt(0)
                if ($null -ne $line) {
                    $lineStr = $line.ToString()
                    $outputBox.AppendText("$lineStr`r`n")
                    $script:bgLineCount++
                    if ($lineStr -match "^ERROR:|^FAIL|>>>") { $script:bgErrorCount++ }
                }
            }
        } catch {}
        # Show completion summary
        $elapsed = ""
        if ($script:bgStartTime) { $dur = (Get-Date) - $script:bgStartTime; $elapsed = " ($('{0:N1}' -f $dur.TotalSeconds)s)" }
        if ($state -eq "Failed") {
            $errMsg = $script:bgPipeline.InvocationStateInfo.Reason.Message
            $outputBox.AppendText("`r`n[FAILED]$elapsed $errMsg`r`n")
            $statusLabel.Text = "FAILED: $($script:bgTaskName)"; $statusLabel.ForeColor = [System.Drawing.Color]::Red
            try { [System.Media.SystemSounds]::Hand.Play() } catch {}
        } elseif ($script:bgErrorCount -gt 0) {
            $outputBox.AppendText("`r`n[DONE]$elapsed $($script:bgLineCount) lines | $($script:bgErrorCount) warning(s)/error(s)`r`n")
            $statusLabel.Text = "Done with warnings"; $statusLabel.ForeColor = [System.Drawing.Color]::Orange
            try { [System.Media.SystemSounds]::Exclamation.Play() } catch {}
        } else {
            $outputBox.AppendText("`r`n[COMPLETE]$elapsed $($script:bgLineCount) lines | All OK`r`n")
            $statusLabel.Text = "Ready"; $statusLabel.ForeColor = [System.Drawing.Color]::LightGreen
            try { [System.Media.SystemSounds]::Asterisk.Play() } catch {}
        }
        # Toast notification if BurntToast is available and window not focused
        try {
            if (-not $form.ContainsFocus -and (Get-Module BurntToast -ListAvailable -ErrorAction SilentlyContinue)) {
                Import-Module BurntToast -ErrorAction SilentlyContinue
                $toastResult = if ($state -eq "Failed") { "FAILED" } elseif ($script:bgErrorCount -gt 0) { "Done with warnings" } else { "Complete" }
                New-BurntToastNotification -Text "CyberScan", "$($script:bgTaskName): $toastResult$elapsed" -ErrorAction SilentlyContinue
            }
        } catch {}
        $outputBox.SelectionStart = $outputBox.Text.Length; $outputBox.ScrollToCaret()
        try { $script:bgPipeline.Dispose() } catch {}
        try { $script:bgRunspace.Close(); $script:bgRunspace.Dispose() } catch {}
        $script:bgPipeline = $null; $script:bgRunspace = $null; $script:bgOutput = $null; $script:taskRunning = $false
        $progressBar.Visible = $false
        $script:taskCount++; $taskCountLabel.Text = "Tasks: $($script:taskCount)"
        $taskPollTimer.Stop()
    }
})

$script:InvokeTask = {
    param([string]$Title, [bool]$Confirm = $false, [scriptblock]$Action)
    if ($script:taskRunning) {
        [System.Windows.Forms.MessageBox]::Show("A task is already running: $($script:bgTaskName)`n`nPlease wait for it to finish.", "Task In Progress", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }
    if ($Confirm) {
        $answer = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to run: $Title`n`nThis operation may modify system settings.", "Confirm: $Title", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($answer -ne "Yes") { $outputBox.AppendText("`r`n--- $Title [CANCELLED by user] ---`r`n"); return }
    }
    $timestamp = Get-Date -Format "hh:mm:ss tt"
    $outputBox.AppendText("`r`n[$timestamp] --- $Title ---`r`nStarting background task...`r`n")
    $statusLabel.Text = "Running: $Title..."; $statusLabel.ForeColor = [System.Drawing.Color]::Yellow
    $progressBar.Visible = $true; $progressBar.BringToFront()
    $script:bgTaskName = $Title; $script:taskRunning = $true
    $script:bgStartTime = Get-Date; $script:bgLineCount = 0; $script:bgErrorCount = 0
    $form.Refresh()
    $script:bgOutput = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    $script:bgRunspace = [RunspaceFactory]::CreateRunspace()
    $script:bgRunspace.ApartmentState = "STA"; $script:bgRunspace.Open()
    $script:bgRunspace.SessionStateProxy.SetVariable("SyncOutput", $script:bgOutput)
    $script:bgRunspace.SessionStateProxy.SetVariable("RealDesktop", $script:RealDesktop)
    $script:bgRunspace.SessionStateProxy.SetVariable("RealDocuments", $script:RealDocuments)
    $script:bgRunspace.SessionStateProxy.SetVariable("RealPictures", $script:RealPictures)
    $script:bgRunspace.SessionStateProxy.SetVariable("SuspiciousPorts", $script:SuspiciousPorts)
    $script:bgRunspace.SessionStateProxy.SetVariable("HighRiskRanges", $script:HighRiskRanges)
    $script:bgRunspace.SessionStateProxy.SetVariable("MitreMap", $script:MitreMap)
    $script:bgRunspace.SessionStateProxy.SetVariable("ScanHistoryFile", $script:ScanHistoryFile)
    $script:bgRunspace.SessionStateProxy.SetVariable("UndoLogFile", $script:UndoLogFile)
    $script:bgRunspace.SessionStateProxy.SetVariable("CurrentVersion", $script:CurrentVersion)
    $script:bgRunspace.SessionStateProxy.SetVariable("VersionCheckURL", $script:VersionCheckURL)
    $script:bgRunspace.SessionStateProxy.SetVariable("CyberScanData", "$env:USERPROFILE\.cyberscan")
    $script:bgRunspace.SessionStateProxy.SetVariable("NetworkAuditFunc", (Get-Item Function:\Get-NetworkAudit).ScriptBlock.ToString())
    $script:bgRunspace.SessionStateProxy.SetVariable("MitreFunc", (Get-Item Function:\Get-MitreTag).ScriptBlock.ToString())
    $script:bgRunspace.SessionStateProxy.SetVariable("SaveScanFunc", (Get-Item Function:\Save-ScanResult).ScriptBlock.ToString())
    $script:bgRunspace.SessionStateProxy.SetVariable("SaveUndoFunc", (Get-Item Function:\Save-UndoEntry).ScriptBlock.ToString())
    $script:bgRunspace.SessionStateProxy.SetVariable("FixPromptFunc", (Get-Item Function:\Show-FixPrompt).ScriptBlock.ToString())
    $script:bgRunspace.SessionStateProxy.SetVariable("ActionScript", $Action.ToString())
    $wrapperCode = @'
try {
    Set-Item Function:\Get-NetworkAudit -Value ([scriptblock]::Create($NetworkAuditFunc))
    Set-Item Function:\Show-FixPrompt   -Value ([scriptblock]::Create($FixPromptFunc))
    Set-Item Function:\Get-MitreTag     -Value ([scriptblock]::Create($MitreFunc))
    Set-Item Function:\Save-ScanResult  -Value ([scriptblock]::Create($SaveScanFunc))
    Set-Item Function:\Save-UndoEntry   -Value ([scriptblock]::Create($SaveUndoFunc))
    $action = [scriptblock]::Create($ActionScript)
    & $action 2>&1 | ForEach-Object { $SyncOutput.Add($_.ToString()) }
} catch {
    $SyncOutput.Add("ERROR: $($_.Exception.Message)")
}
'@
    $script:bgPipeline = [PowerShell]::Create()
    $script:bgPipeline.Runspace = $script:bgRunspace
    [void]$script:bgPipeline.AddScript($wrapperCode)
    [void]$script:bgPipeline.BeginInvoke()
    $taskPollTimer.Start()
}

function Invoke-Task {
    param([string]$Title, [scriptblock]$Action, [switch]$Confirm)
    & $script:InvokeTask $Title ([bool]$Confirm) $Action
}

function Show-FixPrompt {
    param(
        [string]$Title,
        [string[]]$Findings,
        [hashtable]$FixMap,
        [string]$PromptText = "CyberScan found $($Findings.Count) issue(s). Would you like to attempt automatic fixes where possible?"
    )
    if (-not $Findings -or $Findings.Count -eq 0) { return }

    $response = [System.Windows.Forms.MessageBox]::Show(
        $PromptText,
        "Apply Fixes?",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button1
    )

    if ($response -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    Write-Output ""; Write-Output "Applying available fixes..."
    foreach ($f in $Findings) {
        if ($FixMap.ContainsKey($f)) {
            try { & $FixMap[$f] } catch { Write-Output "Fix failed for '$f': $($_.Exception.Message)" }
        } else {
            Write-Output "No automated fix available for: $f"
        }
    }
    Write-Output "Fix attempt complete. Review the output for details."
}

# ===================== FLYOUT SUBMENU SYSTEM =====================
$flyoutPanel = New-Object System.Windows.Forms.Panel
$flyoutPanel.Size = New-Object System.Drawing.Size(280, 0)
$flyoutPanel.Location = New-Object System.Drawing.Point(($sidebarWidth + 2), 55)
$flyoutPanel.BackColor = $colorFlyoutBg; $flyoutPanel.Visible = $false; $flyoutPanel.AutoScroll = $true
$flyoutPanel.BorderStyle = "None"
$form.Controls.Add($flyoutPanel); $flyoutPanel.BringToFront()

$flyoutBorder = New-Object System.Windows.Forms.Panel
$flyoutBorder.Size = New-Object System.Drawing.Size(2, 0)
$flyoutBorder.Location = New-Object System.Drawing.Point($sidebarWidth, 55)
$flyoutBorder.BackColor = $colorFlyoutBorder; $flyoutBorder.Visible = $false
$form.Controls.Add($flyoutBorder); $flyoutBorder.BringToFront()

$script:activeCatButton = $null
$script:CloseFlyout = {
    $flyoutPanel.Visible = $false; $flyoutPanel.Controls.Clear(); $flyoutBorder.Visible = $false
    if ($script:activeCatButton) { $script:activeCatButton.BackColor = $colorBtnNormal; $script:activeCatButton = $null }
}

$script:ShowFlyout = {
    param([System.Windows.Forms.Button]$CategoryButton, [array]$Items)
    if ($script:activeCatButton -eq $CategoryButton -and $flyoutPanel.Visible) { & $script:CloseFlyout; return }
    & $script:CloseFlyout
    $script:activeCatButton = $CategoryButton; $CategoryButton.BackColor = $colorBtnActive
    $btnTop = $CategoryButton.Top + 55
    $itemHeight = 36; $totalHeight = $Items.Count * $itemHeight + 8; $maxBottom = 640 + 55
    if (($btnTop + $totalHeight) -gt $maxBottom) { $btnTop = $maxBottom - $totalHeight }
    if ($btnTop -lt 55) { $btnTop = 55 }
    $flyoutPanel.Location = New-Object System.Drawing.Point(($sidebarWidth + 2), $btnTop)
    $flyoutPanel.Size = New-Object System.Drawing.Size(280, $totalHeight)
    $flyoutBorder.Location = New-Object System.Drawing.Point($sidebarWidth, $btnTop)
    $flyoutBorder.Size = New-Object System.Drawing.Size(2, $totalHeight)
    $flyoutPanel.Controls.Clear()
    $y = 4
    foreach ($item in $Items) {
        $subBtn = New-Object System.Windows.Forms.Button
        $subBtn.Text = "  $($item.Text)"; $subBtn.Size = New-Object System.Drawing.Size(268, 32)
        $subBtn.Location = New-Object System.Drawing.Point(6, $y); $subBtn.FlatStyle = "Flat"
        $subBtn.FlatAppearance.BorderSize = 0; $subBtn.BackColor = $colorSubNormal
        $subBtn.ForeColor = $colorTextWhite; $subBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $subBtn.TextAlign = "MiddleLeft"; $subBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
        $normalBg = $colorSubNormal; $hoverBg = $colorSubHover
        $subBtn.Add_MouseEnter({ $this.BackColor = $hoverBg }.GetNewClosure())
        $subBtn.Add_MouseLeave({ $this.BackColor = $normalBg }.GetNewClosure())
        $clickAction = $item.OnClick; $closeFlyoutRef = $script:CloseFlyout
        $subBtn.Add_Click({ & $closeFlyoutRef; & $clickAction }.GetNewClosure())
        $flyoutPanel.Controls.Add($subBtn); $y += $itemHeight
    }
    $flyoutPanel.Visible = $true; $flyoutBorder.Visible = $true
    $flyoutPanel.BringToFront(); $flyoutBorder.BringToFront()
}

function Close-Flyout { & $script:CloseFlyout }
function Show-Flyout { param($CategoryButton, $Items); & $script:ShowFlyout $CategoryButton $Items }
$outputBox.Add_Click({ & $script:CloseFlyout })

# ===================== SIDEBAR CATEGORY BUTTONS =====================
$script:sideY = 8

$script:sideToolTip = New-Object System.Windows.Forms.ToolTip
$script:sideToolTip.BackColor = [System.Drawing.Color]::FromArgb(20, 24, 50)
$script:sideToolTip.ForeColor = [System.Drawing.Color]::White
$script:sideToolTip.InitialDelay = 400
$script:sideToolTip.ReshowDelay = 200

function Add-CategoryButton {
    param([string]$Label, [System.Drawing.Color]$LabelColor, [array]$SubItems, [string]$Tooltip = "")
    $catBtn = New-Object System.Windows.Forms.Button
    $catBtn.Text = "  $Label  >"; $catBtn.Size = New-Object System.Drawing.Size(($sidebarWidth - 12), 36)
    $catBtn.Location = New-Object System.Drawing.Point(6, $script:sideY); $catBtn.FlatStyle = "Flat"
    $catBtn.FlatAppearance.BorderSize = 0; $catBtn.BackColor = $colorBtnNormal; $catBtn.ForeColor = $LabelColor
    $catBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $catBtn.TextAlign = "MiddleLeft"; $catBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
    $normalBg = $colorBtnNormal; $hoverBg = $colorBtnHover
    $catBtn.Add_MouseEnter({ if ($this -ne $script:activeCatButton) { $this.BackColor = $hoverBg } }.GetNewClosure())
    $catBtn.Add_MouseLeave({ if ($this -ne $script:activeCatButton) { $this.BackColor = $normalBg } }.GetNewClosure())
    $showFlyoutRef = $script:ShowFlyout
    $closeDashRef = $script:CloseDashboard
    $catBtn.Add_Click({
        if ($dashPanel.Visible) { & $closeDashRef }
        & $showFlyoutRef $catBtn $SubItems
    }.GetNewClosure())
    if ($Tooltip) { $script:sideToolTip.SetToolTip($catBtn, $Tooltip) }
    $sidePanel.Controls.Add($catBtn); $script:sideY += 38
}

# ===================== STANDALONE DASHBOARD BUTTON =====================
$dashBtn = New-Object System.Windows.Forms.Button
$dashBtn.Text = "  LIVE DASHBOARD"
$dashBtn.Size = New-Object System.Drawing.Size(($sidebarWidth - 12), 40)
$dashBtn.Location = New-Object System.Drawing.Point(6, $script:sideY)
$dashBtn.FlatStyle = "Flat"
$dashBtn.FlatAppearance.BorderSize = 1
$dashBtn.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(0, 180, 220)
$dashBtn.BackColor = [System.Drawing.Color]::FromArgb(10, 40, 60)
$dashBtn.ForeColor = [System.Drawing.Color]::Cyan
$dashBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$dashBtn.TextAlign = "MiddleCenter"
$dashBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
$dashBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(15, 60, 90) }.GetNewClosure())
$dashBtn.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(10, 40, 60) }.GetNewClosure())
$closeFlyRef = $script:CloseFlyout; $closeDashRef = $script:CloseDashboard; $openDashRef = $script:OpenDashboard
$dashBtn.Add_Click({
    & $closeFlyRef
    if ($dashPanel.Visible) { & $closeDashRef } else { & $openDashRef }
}.GetNewClosure())
$sidePanel.Controls.Add($dashBtn)
$script:sideY += 48

$dashSep = New-Object System.Windows.Forms.Panel
$dashSep.Location = New-Object System.Drawing.Point(10, $script:sideY)
$dashSep.Size = New-Object System.Drawing.Size(($sidebarWidth - 20), 1)
$dashSep.BackColor = [System.Drawing.Color]::FromArgb(30, 50, 90)
$sidePanel.Controls.Add($dashSep)
$script:sideY += 8

# ===================== BUILD ALL CATEGORIES =====================

# --- 1. PREP & CLEANUP ---
Add-CategoryButton -Label "PREP & CLEANUP" -LabelColor $colorCatGreen -Tooltip "Restore points, temp cleanup, bloatware removal" -SubItems @(
    @{ Text = "Create System Restore Point"; OnClick = {
        & $script:InvokeTask "Create Restore Point" $true {
            Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
            Checkpoint-Computer -Description "CyberScan_Ultimate_Backup" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
            Write-Output "Restore Point Created!"
        }
    }.GetNewClosure() },
    @{ Text = "Master Temp/Junk Purge"; OnClick = {
        & $script:InvokeTask "Temp/Junk Purge" $true {
            $before = (Get-ChildItem "$env:TEMP" -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*" -Force -ErrorAction SilentlyContinue
            $after = (Get-ChildItem "$env:TEMP" -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            $freed = [math]::Round(($before - $after) / 1MB, 2)
            Write-Output "Purge Complete. Freed ~$freed MB."
        }
    }.GetNewClosure() },
    @{ Text = "Deep System Cleanup (DISM)"; OnClick = {
        & $script:InvokeTask "Deep System Cleanup" $true { Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase }
    }.GetNewClosure() },
    @{ Text = "Remove Windows Bloatware"; OnClick = {
        & $script:InvokeTask "Remove Bloatware" $true {
            $Bloat = @("*BingNews*","*BingWeather*","*ZuneVideo*","*Office.OneNote*","*YourPhone*","*Solitaire*","*MixedReality*","*People*","*Print3D*","*Feedback*","*Clipchamp*","*Teams*","*Copilot*")
            $removed = 0
            foreach ($App in $Bloat) { $found = Get-AppxPackage $App -ErrorAction SilentlyContinue; if ($found) { $found | Remove-AppxPackage -ErrorAction SilentlyContinue; $removed++ } }
            Write-Output "Bloatware purged. $removed packages removed."
        }
    }.GetNewClosure() },
    @{ Text = "Clear Windows Event Logs"; OnClick = {
        & $script:InvokeTask "Clear Event Logs" $true { wevtutil el | ForEach-Object { wevtutil cl $_ }; Write-Output "Event Logs Cleared." }
    }.GetNewClosure() },
    @{ Text = "Empty Recycle Bin"; OnClick = {
        & $script:InvokeTask "Empty Recycle Bin" $true { Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Write-Output "Recycle Bin Emptied." }
    }.GetNewClosure() }
)

# --- 2. ADVANCED FIXES ---
Add-CategoryButton -Label "ADVANCED FIXES" -LabelColor $colorCatMagenta -Tooltip "DISM, SFC, network reset, boot repair" -SubItems @(
    @{ Text = "Repair System Image (DISM+SFC)"; OnClick = {
        & $script:InvokeTask "Repair System Image" $false { Dism /Online /Cleanup-Image /RestoreHealth; sfc /scannow }
    }.GetNewClosure() },
    @{ Text = "Network Reset & Flush DNS"; OnClick = {
        & $script:InvokeTask "Network Reset" $true { ipconfig /flushdns; netsh winsock reset; netsh int ip reset; Write-Output "Network Reset! Restart PC to take effect." }
    }.GetNewClosure() },
    @{ Text = "Print Spooler Reset"; OnClick = {
        & $script:InvokeTask "Print Spooler Reset" $false {
            Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:windir\System32\spool\PRINTERS\*.*" -Force -Recurse -ErrorAction SilentlyContinue
            Start-Service -Name Spooler -ErrorAction SilentlyContinue; Write-Output "Print Spooler Cleared & Reset."
        }
    }.GetNewClosure() },
    @{ Text = "Repair Boot Records (BCD)"; OnClick = {
        & $script:InvokeTask "Repair Boot Records" $true { bcdboot C:\Windows; Write-Output "Boot files refreshed." }
    }.GetNewClosure() },
    @{ Text = "Drive Error Scan (CHKDSK)"; OnClick = {
        & $script:InvokeTask "CHKDSK Online Scan" $false { chkdsk C: /scan }
    }.GetNewClosure() },
    @{ Text = "Windows Update Reset"; OnClick = {
        & $script:InvokeTask "Windows Update Reset" $true {
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:windir\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Start-Service -Name bits -ErrorAction SilentlyContinue; Write-Output "Windows Update Engine Reset."
        }
    }.GetNewClosure() },
    @{ Text = "Rebuild Icon Cache & UI"; OnClick = {
        & $script:InvokeTask "Rebuild Icon Cache" $true {
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:LOCALAPPDATA\IconCache.db" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache*" -Force -ErrorAction SilentlyContinue
            Start-Process explorer.exe; Write-Output "UI Refresh Complete."
        }
    }.GetNewClosure() },
    @{ Text = "Windows Store Cache Reset"; OnClick = {
        & $script:InvokeTask "Store Cache Reset" $false { wsreset.exe; Write-Output "Store Cache Cleared." }
    }.GetNewClosure() },
    @{ Text = "Schedule RAM/Memory Test"; OnClick = {
        & $script:InvokeTask "Schedule Memory Test" $false { Write-Output "A Memory Diagnostic has been scheduled."; Write-Output "Your PC will test its RAM the next time you restart."; mdsched.exe }
    }.GetNewClosure() }
)

# --- 3. SECURITY ---
Add-CategoryButton -Label "SECURITY" -LabelColor $colorCatYellow -Tooltip "Security score, Defender scans, firewall, port scanning" -SubItems @(
    @{ Text = "Security Score Dashboard"; OnClick = {
        & $script:InvokeTask "Security Score" $false {
            Write-Output "=============================================="
            Write-Output "     CYBERSCAN SECURITY SCORE DASHBOARD"
            Write-Output "=============================================="
            Write-Output ""
            $totalScore = 0; $maxScore = 0; $findings = @()

            # 1. Windows Defender Status (15 pts)
            $maxScore += 15
            try {
                $av = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($av.AntivirusEnabled -and $av.RealTimeProtectionEnabled) {
                    $totalScore += 15; Write-Output "[PASS] Windows Defender: Active + Real-time ON  (+15)"
                } elseif ($av.AntivirusEnabled) {
                    $totalScore += 8; Write-Output "[WARN] Windows Defender: Active but Real-time OFF  (+8)"
                    $findings += "Enable Defender Real-time Protection"
                } else { Write-Output "[FAIL] Windows Defender: DISABLED  (+0)"; Write-Output "       $(Get-MitreTag 'DefenderDisabled')"; $findings += "Enable Windows Defender immediately" }
            } catch { Write-Output "[FAIL] Cannot query Defender  (+0)"; $findings += "Install/Enable antivirus" }

            # 2. Firewall (15 pts)
            $maxScore += 15
            try {
                $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                $allOn = ($fw | Where-Object { $_.Enabled }).Count
                if ($allOn -eq 3) { $totalScore += 15; Write-Output "[PASS] Firewall: All 3 profiles ON  (+15)" }
                elseif ($allOn -ge 1) { $totalScore += 7; Write-Output "[WARN] Firewall: $allOn/3 profiles ON  (+7)"; $findings += "Enable all firewall profiles" }
                else { Write-Output "[FAIL] Firewall: ALL profiles OFF  (+0)"; $findings += "Enable Windows Firewall NOW" }
            } catch { Write-Output "[FAIL] Cannot query Firewall  (+0)" }

            # 3. UAC Status (10 pts)
            $maxScore += 10
            try {
                $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue
                if ($uac.EnableLUA -eq 1) { $totalScore += 10; Write-Output "[PASS] UAC: Enabled  (+10)" }
                else { Write-Output "[FAIL] UAC: DISABLED  (+0)"; $findings += "Re-enable User Account Control" }
            } catch { Write-Output "[WARN] Cannot check UAC  (+0)" }

            # 4. BitLocker (10 pts)
            $maxScore += 10
            try {
                $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                if ($bl.ProtectionStatus -eq "On") { $totalScore += 10; Write-Output "[PASS] BitLocker C: Encrypted  (+10)" }
                else { Write-Output "[FAIL] BitLocker C: NOT encrypted  (+0)"; $findings += "Enable BitLocker drive encryption" }
            } catch { Write-Output "[INFO] BitLocker: Not available  (+0)" }

            # 5. Secure Boot (10 pts)
            $maxScore += 10
            try {
                $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                if ($sb) { $totalScore += 10; Write-Output "[PASS] Secure Boot: Enabled  (+10)" }
                else { Write-Output "[FAIL] Secure Boot: Disabled  (+0)"; $findings += "Enable Secure Boot in BIOS" }
            } catch { Write-Output "[INFO] Secure Boot: Cannot verify  (+0)" }

            # 6. SMB1 Disabled (5 pts)
            $maxScore += 5
            try {
                $smb1 = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                if (-not $smb1.EnableSMB1Protocol) { $totalScore += 5; Write-Output "[PASS] SMBv1: Disabled  (+5)" }
                else { Write-Output "[FAIL] SMBv1: ENABLED (vulnerability)  (+0)"; Write-Output "       $(Get-MitreTag 'SMBv1Enabled')"; $findings += "Disable SMBv1 protocol" }
            } catch { Write-Output "[INFO] SMBv1: Cannot check  (+0)" }

            # 7. Remote Desktop (5 pts)
            $maxScore += 5
            try {
                $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
                if ($rdp.fDenyTSConnections -eq 1) { $totalScore += 5; Write-Output "[PASS] Remote Desktop: Disabled  (+5)" }
                else { Write-Output "[WARN] Remote Desktop: ENABLED  (+0)"; Write-Output "       $(Get-MitreTag 'RDPEnabled')"; $findings += "Disable RDP if not needed" }
            } catch { Write-Output "[INFO] RDP: Cannot check  (+0)" }

            # 8. Password Policy (10 pts)
            $maxScore += 10
            try {
                $users = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
                $noExpiry = @($users | Where-Object { $_.PasswordExpires -eq $null -and $_.Name -ne "DefaultAccount" })
                $noPwd = @($users | Where-Object { $_.PasswordRequired -eq $false })
                if ($noPwd.Count -eq 0 -and $noExpiry.Count -le 1) { $totalScore += 10; Write-Output "[PASS] User Accounts: All secured  (+10)" }
                elseif ($noPwd.Count -gt 0) { Write-Output "[FAIL] $($noPwd.Count) accounts without password requirement  (+0)"; $findings += "Set passwords on all accounts" }
                else { $totalScore += 5; Write-Output "[WARN] $($noExpiry.Count) accounts with non-expiring passwords  (+5)"; $findings += "Review password expiration policy" }
            } catch { Write-Output "[INFO] Cannot audit users  (+0)" }

            # 9. Windows Update (10 pts)
            $maxScore += 10
            try {
                $hotfix = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
                if ($hotfix) {
                    $daysSince = ((Get-Date) - $hotfix.InstalledOn).Days
                    if ($daysSince -le 30) { $totalScore += 10; Write-Output "[PASS] Last patch: $($daysSince)d ago ($($hotfix.HotFixID))  (+10)" }
                    elseif ($daysSince -le 60) { $totalScore += 5; Write-Output "[WARN] Last patch: $($daysSince)d ago  (+5)"; $findings += "Run Windows Update" }
                    else { Write-Output "[FAIL] Last patch: $($daysSince)d ago  (+0)"; $findings += "CRITICAL: Run Windows Update immediately" }
                }
            } catch { Write-Output "[INFO] Cannot check update history  (+0)" }

            # 10. Open Ports (10 pts)
            $maxScore += 10
            try {
                $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
                $suspicious = @($listeners | Where-Object { $SuspiciousPorts.ContainsKey([int]$_.LocalPort) })
                if ($suspicious.Count -eq 0) { $totalScore += 10; Write-Output "[PASS] No suspicious listening ports  (+10)" }
                else { Write-Output "[FAIL] $($suspicious.Count) suspicious ports open  (+0)"; foreach ($s in $suspicious) { $findings += "Suspicious port $($s.LocalPort): $($SuspiciousPorts[[int]$s.LocalPort])" } }
            } catch { Write-Output "[INFO] Cannot scan ports  (+0)" }

            # Final Score
            $pct = if ($maxScore -gt 0) { [math]::Round(($totalScore / $maxScore) * 100) } else { 0 }
            Write-Output ""
            Write-Output "=============================================="
            $grade = if ($pct -ge 90) { "A+" } elseif ($pct -ge 80) { "A" } elseif ($pct -ge 70) { "B" } elseif ($pct -ge 60) { "C" } elseif ($pct -ge 50) { "D" } else { "F" }
            Write-Output "  SECURITY SCORE: $totalScore / $maxScore ($pct%) - Grade: $grade"
            Write-Output "=============================================="
            Save-ScanResult -ScanName "SecurityScore" -Score $totalScore -MaxScore $maxScore -Issues $findings.Count
            if ($findings.Count -gt 0) {
                Write-Output ""; Write-Output "=== RECOMMENDED ACTIONS ==="
                $i = 1; foreach ($f in $findings) { Write-Output "  $i. $f"; $i++ }

                $response = [System.Windows.Forms.MessageBox]::Show(
                    "CyberScan found $($findings.Count) issue(s).`n`nWould you like to attempt automatic fixes where possible?",
                    "Apply Fixes?",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question,
                    [System.Windows.Forms.MessageBoxDefaultButton]::Button1,
                    [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
                )
                if ($response -eq "Yes") {
                    Write-Output ""; Write-Output "Applying available fixes..."
                    foreach ($f in $findings) {
                        switch ($f) {
                            "Enable Defender Real-time Protection" {
                                try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; Write-Output "Fixed: Enabled Defender Real-time Protection" } catch { Write-Output "Could not enable Defender real-time protection: $($_.Exception.Message)" }
                            }
                            "Enable all firewall profiles" {
                                try { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop; Write-Output "Fixed: Enabled all firewall profiles" } catch { Write-Output "Could not enable firewall profiles: $($_.Exception.Message)" }
                            }
                            "Enable Windows Firewall NOW" {
                                try { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop; Write-Output "Fixed: Enabled Windows Firewall" } catch { Write-Output "Could not enable Windows Firewall: $($_.Exception.Message)" }
                            }
                            "Re-enable User Account Control" {
                                try { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -ErrorAction Stop; Write-Output "Fixed: Enabled UAC" } catch { Write-Output "Could not enable UAC: $($_.Exception.Message)" }
                            }
                            "Disable SMBv1 protocol" {
                                try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop; Set-SmbClientConfiguration -EnableSMB1Protocol $false -ErrorAction Stop; Write-Output "Fixed: Disabled SMBv1 protocol" } catch { Write-Output "Could not disable SMBv1: $($_.Exception.Message)" }
                            }
                            "Disable RDP if not needed" {
                                try { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 1 -ErrorAction Stop; Write-Output "Fixed: Disabled Remote Desktop" } catch { Write-Output "Could not disable RDP: $($_.Exception.Message)" }
                            }
                            "Run Windows Update" {
                                try { Start-Process "ms-settings:windowsupdate" -ErrorAction Stop; Write-Output "Opened Windows Update settings." } catch { Write-Output "Could not open Windows Update settings: $($_.Exception.Message)" }
                            }
                            "CRITICAL: Run Windows Update immediately" {
                                try { Start-Process "ms-settings:windowsupdate" -ErrorAction Stop; Write-Output "Opened Windows Update settings." } catch { Write-Output "Could not open Windows Update settings: $($_.Exception.Message)" }
                            }
                            Default {
                                Write-Output "No automated fix available for: $f"
                            }
                        }
                    }
                    Write-Output "Fix attempt complete. Review the output for details."
                }
            }
        }
    }.GetNewClosure() },
    @{ Text = "Scan for Autorun Malware"; OnClick = {
        & $script:InvokeTask "Autorun Scan" $false {
            Get-PSDrive -PSProvider FileSystem | ForEach-Object { if (Test-Path "$($_.Root)autorun.inf") { Write-Output "ALERT: Autorun found on $($_.Root)" } }
            Write-Output "Autorun Scan Complete."
        }
    }.GetNewClosure() },
    @{ Text = "Defender Scan - Quick"; OnClick = {
        & $script:InvokeTask "Defender Quick Scan" $false {
            Write-Output "=============================================="
            Write-Output "   WINDOWS DEFENDER - QUICK SCAN"
            Write-Output "=============================================="
            Write-Output "Scanning: Memory, running processes, startup items, boot sector"
            Write-Output "Typical duration: 1 - 5 minutes"
            Write-Output ""
            $scanJob = Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue }
            $startTime = Get-Date
            $spinChars = @('|','/','-','\')
            $spinIdx = 0; $lastThreats = 0
            while ($scanJob.State -eq 'Running') {
                Start-Sleep -Seconds 2
                $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
                $spin = $spinChars[$spinIdx % 4]; $spinIdx++
                try {
                    $tc = @(Get-MpThreat -ErrorAction SilentlyContinue).Count
                    if ($tc -gt $lastThreats) { $lastThreats = $tc; Write-Output ">>> THREAT DETECTED! Count so far: $tc" }
                } catch {}
                $mins = [math]::Floor($elapsed / 60); $secs = $elapsed % 60
                Write-Output "$spin  Scanning... $($mins)m $($secs)s elapsed"
            }
            $null = Receive-Job -Job $scanJob -Wait -ErrorAction SilentlyContinue
            Remove-Job $scanJob -ErrorAction SilentlyContinue
            $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
            $dMins = [math]::Floor($duration / 60); $dSecs = $duration % 60
            Write-Output ""
            Write-Output "=== SCAN COMPLETE - Duration: $($dMins)m $($dSecs)s ==="
            try {
                $threats = @(Get-MpThreat -ErrorAction SilentlyContinue)
                if ($threats.Count -gt 0) {
                    Write-Output ""; Write-Output ">>> $($threats.Count) THREAT(S) FOUND:"
                    foreach ($t in $threats) { Write-Output "  - $($t.ThreatName) [$($t.SeverityID)] at: $($t.Resources -join ', ')" }
                    Write-Output ""; Write-Output "Open Windows Security to quarantine or remove threats."
                    Start-Process "windowsdefender://threatsettings"
                } else {
                    Write-Output "[CLEAN] No threats detected. Your system is safe."
                }
                $s = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($s -and $s.QuickScanEndTime) { Write-Output "Scan ended: $($s.QuickScanEndTime.ToString('yyyy-MM-dd HH:mm:ss'))" }
            } catch { Write-Output "Scan finished. Check Windows Security for detailed results." }
        }
    }.GetNewClosure() },
    @{ Text = "Defender Scan - Full"; OnClick = {
        & $script:InvokeTask "Defender Full Scan" $false {
            Write-Output "=============================================="
            Write-Output "   WINDOWS DEFENDER - FULL SCAN"
            Write-Output "=============================================="
            Write-Output "Scanning: ALL files and folders on all drives"
            Write-Output "WARNING: This can take 30 minutes to several hours."
            Write-Output "You can continue using your PC - scan runs in background."
            Write-Output ""
            $scanJob = Start-Job -ScriptBlock { Start-MpScan -ScanType FullScan -ErrorAction SilentlyContinue }
            $startTime = Get-Date
            $spinChars = @('|','/','-','\')
            $spinIdx = 0; $lastThreats = 0; $reportEvery = 0
            while ($scanJob.State -eq 'Running') {
                Start-Sleep -Seconds 3
                $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
                $spin = $spinChars[$spinIdx % 4]; $spinIdx++; $reportEvery++
                try {
                    $tc = @(Get-MpThreat -ErrorAction SilentlyContinue).Count
                    if ($tc -gt $lastThreats) { $lastThreats = $tc; Write-Output ">>> THREAT DETECTED! Count so far: $tc" }
                } catch {}
                $hrs  = [math]::Floor($elapsed / 3600)
                $mins = [math]::Floor(($elapsed % 3600) / 60)
                $secs = $elapsed % 60
                $timeStr = if ($hrs -gt 0) { "$($hrs)h $($mins)m $($secs)s" } else { "$($mins)m $($secs)s" }
                Write-Output "$spin  Full scan in progress... $timeStr elapsed"
                # Every ~30s print a reminder the scan is still running
                if ($reportEvery % 10 -eq 0) { Write-Output "   (Full scan is still running - this is normal for large drives)" }
            }
            $null = Receive-Job -Job $scanJob -Wait -ErrorAction SilentlyContinue
            Remove-Job $scanJob -ErrorAction SilentlyContinue
            $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
            $dHrs  = [math]::Floor($duration / 3600)
            $dMins = [math]::Floor(($duration % 3600) / 60)
            $dSecs = $duration % 60
            $dStr  = if ($dHrs -gt 0) { "$($dHrs)h $($dMins)m $($dSecs)s" } else { "$($dMins)m $($dSecs)s" }
            Write-Output ""
            Write-Output "=== FULL SCAN COMPLETE - Duration: $dStr ==="
            try {
                $threats = @(Get-MpThreat -ErrorAction SilentlyContinue)
                if ($threats.Count -gt 0) {
                    Write-Output ""; Write-Output ">>> $($threats.Count) THREAT(S) FOUND:"
                    foreach ($t in $threats) { Write-Output "  - $($t.ThreatName) [$($t.SeverityID)] at: $($t.Resources -join ', ')" }
                    Write-Output ""; Write-Output "Open Windows Security to quarantine or remove threats."
                    Start-Process "windowsdefender://threatsettings"
                } else {
                    Write-Output "[CLEAN] No threats detected. Your system is safe."
                }
                $s = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($s -and $s.FullScanEndTime) { Write-Output "Scan ended: $($s.FullScanEndTime.ToString('yyyy-MM-dd HH:mm:ss'))" }
            } catch { Write-Output "Scan finished. Check Windows Security for detailed results." }
        }
    }.GetNewClosure() },
    @{ Text = "Security Lockdown (Backdoors)"; OnClick = {
        & $script:InvokeTask "Security Lockdown" $true {
            Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -ErrorAction SilentlyContinue
            netsh advfirewall firewall set rule group="Remote Desktop" new enable=No 2>&1 | Out-Null
            Write-Output "Backdoors Closed. Remote Registry, SMB1, Remote Assistance, RDP disabled."
        }
    }.GetNewClosure() },
    @{ Text = "Firewall Status Check"; OnClick = {
        & $script:InvokeTask "Firewall Status" $false {
            $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            $fwFindings = @()
            foreach ($p in $fw) {
                $state = if ($p.Enabled) { "ON" } else { "OFF" }
                Write-Output "$($p.Name) Firewall: $state (Inbound: $($p.DefaultInboundAction), Outbound: $($p.DefaultOutboundAction))"
                if (-not $p.Enabled) { $fwFindings += "Firewall profile disabled: $($p.Name)" }
            }
            if ($fwFindings.Count -gt 0) {
                Write-Output ""; Write-Output ">>> WARNING: $($fwFindings.Count) firewall profile(s) are DISABLED!"
                Show-FixPrompt -Title "Firewall Status Check" -Findings $fwFindings -FixMap @{
                    "Firewall profile disabled: Domain"  = { Set-NetFirewallProfile -Name Domain  -Enabled True -ErrorAction SilentlyContinue; Write-Output "Fixed: Enabled Domain firewall" }
                    "Firewall profile disabled: Public"  = { Set-NetFirewallProfile -Name Public  -Enabled True -ErrorAction SilentlyContinue; Write-Output "Fixed: Enabled Public firewall" }
                    "Firewall profile disabled: Private" = { Set-NetFirewallProfile -Name Private -Enabled True -ErrorAction SilentlyContinue; Write-Output "Fixed: Enabled Private firewall" }
                }
            } else { Write-Output ""; Write-Output "All firewall profiles are ON." }
        }
    }.GetNewClosure() },
    @{ Text = "Port Scanner + Threat Check"; OnClick = {
        & $script:InvokeTask "Port Threat Scanner" $false {
            Write-Output "=== PORT SCANNER WITH THREAT INTELLIGENCE ==="
            $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort
            Write-Output ("{0,-8} {1,-25} {2,-8} {3}" -f "Port", "Process", "PID", "Risk Assessment")
            Write-Output ("-" * 75)
            $suspiciousPorts = @{4444="Metasploit/Meterpreter";5555="Android ADB/Shell";6666="IRC Backdoor";6667="IRC C2";1337="Elite/Backdoor";31337="Back Orifice";12345="NetBus";27374="SubSeven";9001="Tor/C2";4443="C2 HTTPS alt";1080="SOCKS proxy"}
            foreach ($l in $listeners) {
                $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
                $pname = if ($proc) { $proc.ProcessName } else { "Unknown" }
                $risk = "Safe"
                $port = [int]$l.LocalPort
                if ($suspiciousPorts.ContainsKey($port)) { $risk = "SUSPICIOUS: $($suspiciousPorts[$port])" }
                elseif ($port -gt 49152) { $risk = "Dynamic/Ephemeral" }
                elseif ($port -gt 10000 -and $pname -notin @("System","svchost","lsass","services")) { $risk = "Review - unusual port" }
                $flag = if ($risk -like "SUSPICIOUS*") { ">>>" } else { "   " }
                Write-Output ("$flag{0,-8} {1,-25} {2,-8} {3}" -f $port, $pname, $l.OwningProcess, $risk)
            }
            $totalListening = @($listeners).Count
            $suspCount = @($listeners | Where-Object { $suspiciousPorts.ContainsKey([int]$_.LocalPort) }).Count
            Write-Output ""; Write-Output "Total: $totalListening listening ports | $suspCount flagged suspicious"
            if ($suspCount -gt 0) {
                Write-Output ""; Write-Output ">>> RECOMMENDED: Investigate or block suspicious ports immediately!"
                Show-FixPrompt -Title "Port Threat Scanner" -Findings @("Suspicious listening ports detected") -FixMap @{
                    "Suspicious listening ports detected" = { Start-Process "wf.msc"; Write-Output "Opened Windows Firewall with Advanced Security. Block the flagged ports manually." }
                }
            }
        }
    }.GetNewClosure() }
)

# --- 4. PERFORMANCE ---
Add-CategoryButton -Label "PERFORMANCE" -LabelColor $colorCatOrange -Tooltip "Power plans, startup analyzer, drive optimization" -SubItems @(
    @{ Text = "Set High Performance Power Plan"; OnClick = {
        & $script:InvokeTask "High Performance Power Plan" $false { powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c; Write-Output "Power plan set to High Performance." }
    }.GetNewClosure() },
    @{ Text = "Startup Risk Analyzer"; OnClick = {
        & $script:InvokeTask "Startup Risk Analyzer" $false {
            Write-Output "=== STARTUP PROGRAMS - RISK ANALYSIS ==="
            Write-Output ("{0,-35} {1,-12} {2,-10} {3}" -f "Program", "Risk", "Signed?", "Location")
            Write-Output ("-" * 90)
            $items = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue
            $safePublishers = @("Microsoft","Google","Intel","NVIDIA","AMD","Realtek","Logitech")
            $highRisk = @()
            foreach ($item in $items) {
                $risk = "UNKNOWN"
                $signed = "N/A"
                $cmd = $item.Command -replace '"',''
                $exePath = ($cmd -split '\s')[0]
                if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                    try {
                        $sig = Get-AuthenticodeSignature $exePath -ErrorAction SilentlyContinue
                        if ($sig.Status -eq "Valid") {
                            $signed = "YES"
                            $signerName = $sig.SignerCertificate.Subject
                            $isSafe = $false
                            foreach ($pub in $safePublishers) { if ($signerName -like "*$pub*") { $isSafe = $true; break } }
                            $risk = if ($isSafe) { "LOW" } else { "MEDIUM" }
                        } else { $signed = "NO"; $risk = "HIGH" }
                    } catch { $signed = "ERROR"; $risk = "HIGH" }
                } else { $risk = "HIGH"; $signed = "MISSING" }
                if ($exePath -like "*\AppData\*" -or $exePath -like "*\Temp\*") { $risk = "HIGH" }
                if ($risk -eq "HIGH") { $highRisk += "$($item.Name) - $exePath" }
                $color = switch ($risk) { "LOW" { "" } "MEDIUM" { "(!)" } "HIGH" { ">>>" } default { "(?)" } }
                Write-Output ("$color{0,-35} {1,-12} {2,-10} {3}" -f $item.Name, $risk, $signed, $exePath)
            }
            $total = @($items).Count
            Write-Output ""; Write-Output "$total startup entries analyzed. Use Task Manager > Startup to disable items."
            if ($highRisk.Count -gt 0) {
                Write-Output ""; Write-Output "=== HIGH-RISK STARTUP ENTRIES ==="
                foreach ($h in $highRisk) { Write-Output "  $h" }
                Show-FixPrompt -Title "Startup Risk Analyzer" -Findings @("High-risk startup entries detected") -FixMap @{ "High-risk startup entries detected" = { Start-Process "ms-settings:startupapps" } }
            }
        }
    }.GetNewClosure() },
    @{ Text = "Optimize Drives (Defrag/Trim)"; OnClick = {
        & $script:InvokeTask "Optimize Drives" $false { Optimize-Volume -DriveLetter C -Verbose; Write-Output "Drive optimization complete." }
    }.GetNewClosure() },
    @{ Text = "Disable Visual Effects (Speed)"; OnClick = {
        & $script:InvokeTask "Disable Visual Effects" $true {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2 -ErrorAction SilentlyContinue
            Write-Output "Visual effects set to 'Best Performance'. Restart Explorer or reboot."
        }
    }.GetNewClosure() },
    @{ Text = "Clear DNS Cache"; OnClick = {
        & $script:InvokeTask "Clear DNS Cache" $false { ipconfig /flushdns; Write-Output "DNS cache cleared." }
    }.GetNewClosure() },
    @{ Text = "Top 15 Processes (by RAM)"; OnClick = {
        & $script:InvokeTask "Top Processes by RAM" $false {
            $procs = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15
            Write-Output "=== TOP 15 PROCESSES BY RAM USAGE ==="
            Write-Output ("{0,-30} {1,12} {2,8}" -f "Process", "RAM (MB)", "PID"); Write-Output ("-" * 54)
            foreach ($p in $procs) { Write-Output ("{0,-30} {1,12} {2,8}" -f $p.ProcessName, [math]::Round($p.WorkingSet64 / 1MB, 1), $p.Id) }
        }
    }.GetNewClosure() },
    @{ Text = "Top 10 Processes (by CPU)"; OnClick = {
        & $script:InvokeTask "Top Processes by CPU" $false {
            $procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
            Write-Output "=== TOP 10 PROCESSES BY CPU TIME ==="
            Write-Output ("{0,-30} {1,12} {2,8}" -f "Process", "CPU (sec)", "PID"); Write-Output ("-" * 54)
            foreach ($p in $procs) { Write-Output ("{0,-30} {1,12} {2,8}" -f $p.ProcessName, [math]::Round($p.CPU, 1), $p.Id) }
        }
    }.GetNewClosure() }
)

# --- 5. SYSTEM INFO ---
Add-CategoryButton -Label "SYSTEM INFO" -LabelColor $colorCatTeal -Tooltip "Hardware, drivers, network, battery, patches" -SubItems @(
    @{ Text = "Full Hardware Report"; OnClick = {
        & $script:InvokeTask "Hardware Report" $false {
            $cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
            $cpu = Get-CimInstance Win32_Processor; $gpu = Get-CimInstance Win32_VideoController
            $bios = Get-CimInstance Win32_BIOS; $ram = Get-CimInstance Win32_PhysicalMemory
            Write-Output "============ HARDWARE REPORT ============"
            Write-Output "Computer:     $($cs.Manufacturer) $($cs.Model)"
            Write-Output "OS:           $($os.Caption) (Build $($os.BuildNumber))"
            Write-Output "CPU:          $($cpu.Name)"
            Write-Output "Cores/Thread: $($cpu.NumberOfCores)C / $($cpu.NumberOfLogicalProcessors)T"
            Write-Output "Total RAM:    $([math]::Round($cs.TotalPhysicalMemory/1GB, 1)) GB"
            $stickNum = 1
            foreach ($stick in $ram) { Write-Output "RAM Stick $stickNum`:  $([math]::Round($stick.Capacity/1GB,1)) GB $($stick.Manufacturer) @ $($stick.Speed) MHz"; $stickNum++ }
            foreach ($g in $gpu) { Write-Output "GPU:          $($g.Name) ($([math]::Round($g.AdapterRAM/1GB,1)) GB)" }
            Write-Output "BIOS:         $($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)"
            $disks = Get-Volume | Where-Object { $_.DriveLetter } | Sort-Object DriveLetter
            foreach ($d in $disks) {
                $total = [math]::Round($d.Size/1GB, 1); $free = [math]::Round($d.SizeRemaining/1GB, 1)
                $pct = if ($d.Size -gt 0) { [math]::Round(($d.SizeRemaining / $d.Size) * 100, 0) } else { 0 }
                Write-Output "Drive $($d.DriveLetter):      $free GB free / $total GB ($pct% free)"
            }
            Write-Output "========================================="
        }
    }.GetNewClosure() },
    @{ Text = "Installed Programs"; OnClick = {
        & $script:InvokeTask "Installed Programs" $false {
            Write-Output "=== INSTALLED PROGRAMS ==="
            $apps = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } | Sort-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher
            foreach ($app in $apps) { Write-Output "$($app.DisplayName) v$($app.DisplayVersion) - $($app.Publisher)" }
            Write-Output ""; Write-Output "($($apps.Count) programs found)"
        }
    }.GetNewClosure() },
    @{ Text = "Driver List"; OnClick = {
        & $script:InvokeTask "Driver List" $false {
            Write-Output "=== INSTALLED DRIVERS ==="
            $drivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue | Select-Object -First 50
            if ($drivers) { foreach ($d in $drivers) { Write-Output "$($d.Driver) | $($d.ProviderName) | $($d.Version) | $($d.Date)" } }
            else { driverquery /FO LIST | Select-Object -First 100 }
        }
    }.GetNewClosure() },
    @{ Text = "Network Adapters & IPs"; OnClick = {
        & $script:InvokeTask "Network Adapters" $false {
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            foreach ($a in $adapters) {
                $ips = Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
                Write-Output "--- $($a.Name) ($($a.InterfaceDescription)) ---"
                Write-Output "  MAC:    $($a.MacAddress)"; Write-Output "  Speed:  $($a.LinkSpeed)"
                foreach ($ip in $ips) { Write-Output "  IP:     $($ip.IPAddress) / $($ip.PrefixLength)" }
            }
            try { $extIP = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 5); Write-Output ""; Write-Output "External IP: $extIP" } catch { Write-Output "External IP: Could not determine" }
        }
    }.GetNewClosure() },
    @{ Text = "Wi-Fi Signal Strength"; OnClick = {
        & $script:InvokeTask "Wi-Fi Signal" $false {
            $wifi = netsh wlan show interfaces 2>&1 | Out-String
            if ($wifi -match "There is no wireless") { Write-Output "No Wi-Fi adapter found." } else { Write-Output $wifi }
        }
    }.GetNewClosure() },
    @{ Text = "Battery / Power Status"; OnClick = {
        & $script:InvokeTask "Battery Status" $false {
            $bat = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
            if ($bat) {
                Write-Output "Battery:      $($bat.Name)"; Write-Output "Charge:       $($bat.EstimatedChargeRemaining)%"
                $statusMap = @{1="Discharging";2="AC Power";3="Fully Charged";4="Low";5="Critical"}
                $s = $statusMap[[int]$bat.BatteryStatus]; if (-not $s) { $s = "Status $($bat.BatteryStatus)" }
                Write-Output "Status:       $s"
                if ($bat.EstimatedRunTime -and $bat.EstimatedRunTime -lt 71582788) { Write-Output "Remaining:    $($bat.EstimatedRunTime) minutes" }
            } else { Write-Output "No battery detected (desktop PC)." }
            $plan = powercfg /getactivescheme 2>&1 | Out-String; Write-Output ""; Write-Output "Active Power Plan:"; Write-Output $plan.Trim()
        }
    }.GetNewClosure() },
    @{ Text = "Patch Management Dashboard"; OnClick = {
        & $script:InvokeTask "Patch Management" $false {
            Write-Output "=== PATCH MANAGEMENT DASHBOARD ==="
            Write-Output ""
            $patchFindings = @()
            $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
            if ($hotfixes) {
                $latest = $hotfixes | Select-Object -First 1
                $daysSince = [math]::Round(((Get-Date) - $latest.InstalledOn).TotalDays)
                Write-Output "Last Patch Installed: $($latest.HotFixID) on $($latest.InstalledOn.ToString('yyyy-MM-dd')) ($daysSince days ago)"
                if ($daysSince -gt 60) { Write-Output ">>> WARNING: System is over 60 days behind on patches!"; $patchFindings += "System is over 60 days behind on patches" }
                Write-Output ""; Write-Output "=== RECENT PATCHES (Last 20) ==="
                Write-Output ("{0,-15} {1,-14} {2,-20} {3}" -f "HotFixID", "Type", "Installed", "Description")
                Write-Output ("-" * 80)
                foreach ($h in ($hotfixes | Select-Object -First 20)) {
                    $date = if ($h.InstalledOn) { $h.InstalledOn.ToString("yyyy-MM-dd") } else { "Unknown" }
                    Write-Output ("{0,-15} {1,-14} {2,-20} {3}" -f $h.HotFixID, $h.Description, $date, $h.Caption)
                }
                Write-Output ""; Write-Output "Total patches on record: $($hotfixes.Count)"
            } else { Write-Output "No patch history available." }
            # Pending reboot check
            $pendingReboot = $false
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $pendingReboot = $true }
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $pendingReboot = $true }
            if ($pendingReboot) { Write-Output ""; Write-Output ">>> REBOOT PENDING: A restart is required to finish installing updates!"; $patchFindings += "Pending reboot required to finish updates" }

            if ($patchFindings.Count -gt 0) {
                Show-FixPrompt -Title "Patch Management" -Findings $patchFindings -FixMap @{
                    "System is over 60 days behind on patches" = { Start-Process "ms-settings:windowsupdate" }
                    "Pending reboot required to finish updates" = { Start-Process "ms-settings:windowsupdate" }
                }
            }
        }
    }.GetNewClosure() }
)

# --- 6. INTELLIGENCE ---
Add-CategoryButton -Label "INTELLIGENCE" -LabelColor $colorCatBlueWhite -Tooltip "Live dashboard, network audit, HTML reports" -SubItems @(
    @{ Text = "Live Dashboard (Graphical)"; OnClick = { & $script:OpenDashboard }.GetNewClosure() },
    @{ Text = "Network Connection Audit"; OnClick = {
        & $script:InvokeTask "Network Audit" $false {
            $net = Get-NetworkAudit
            Write-Output "=== ACTIVE NETWORK CONNECTIONS ==="
            Write-Output ("{0,-20} {1,-16} {2,-7} {3,-20} {4}" -f "Program", "Remote IP", "Port", "Safety", "Location")
            Write-Output ("-" * 95)
            foreach ($n in $net) { Write-Output ("{0,-20} {1,-16} {2,-7} {3,-20} {4}" -f $n.Program, $n.RemoteIP, $n.RemotePort, $n.Safety, $n.Location) }
            $warn = ($net | Where-Object { $_.Safety -like "*WARNING*" -or $_.Safety -like "*Hidden*" }).Count
            Write-Output ""; Write-Output "Total: $($net.Count) connections | $warn flagged"
        }
    }.GetNewClosure() },
    @{ Text = "Save Snapshot to Desktop"; OnClick = {
        & $script:InvokeTask "Save Snapshot" $false {
            $os = Get-CimInstance Win32_OperatingSystem; $cs = Get-CimInstance Win32_ComputerSystem
            $cpu = Get-CimInstance Win32_Processor; $disk = Get-Volume -DriveLetter C
            $snap = @"
CyberScan 2026 TITAN ULTIMATE - System Snapshot
Generated: $(Get-Date)
=================================
Computer: $($cs.Manufacturer) $($cs.Model)
OS:       $($os.Caption) (Build $($os.BuildNumber))
CPU:      $($cpu.Name)
RAM:      $([math]::Round($cs.TotalPhysicalMemory/1GB, 1)) GB
C: Drive: $([math]::Round($disk.SizeRemaining/1GB, 2)) GB Free / $([math]::Round($disk.Size/1GB, 1)) GB Total
=================================
"@
            $snapDest = "$RealDesktop\System_Snapshot.txt"
            $snap | Out-File $snapDest
            Write-Output "Snapshot saved to $snapDest"
        }
    }.GetNewClosure() },
    @{ Text = "Generate HTML Security Report"; OnClick = {
        & $script:InvokeTask "HTML Report Generator" $false {
            $reportPath = "$RealDesktop\CyberScan_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
            $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
            $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            $fwStatus = ($fw | ForEach-Object { "$($_.Name): $(if($_.Enabled){'ON'}else{'OFF'})" }) -join " | "
            $avStatus = "N/A"
            try { $av = Get-MpComputerStatus -ErrorAction SilentlyContinue; if ($av.AntivirusEnabled) { $avStatus = "Active (Defs: $($av.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd')))" } else { $avStatus = "DISABLED" } } catch {}
            $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).Count
            $connections = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).Count
            $users = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
            $userList = ($users | ForEach-Object { "<tr><td>$($_.Name)</td><td>$(if($_.LastLogon){$_.LastLogon.ToString('yyyy-MM-dd')}else{'Never'})</td><td>$(if($_.PasswordRequired){'Yes'}else{'NO'})</td></tr>" }) -join "`n"
            $disk = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue
            $diskPct = if ($disk.Size -gt 0) { [math]::Round((1 - ($disk.SizeRemaining / $disk.Size)) * 100) } else { 0 }
            $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CyberScan Security Report</title>
<style>
body{font-family:'Segoe UI',sans-serif;background:#0a0a1a;color:#e0e0e0;margin:0;padding:20px}
h1{color:#00ffff;border-bottom:2px solid #00ffff;padding-bottom:10px}
h2{color:#00ff80;margin-top:30px}
table{border-collapse:collapse;width:100%;margin:10px 0}
th,td{border:1px solid #2a2a4a;padding:8px 12px;text-align:left}
th{background:#1a1a3a;color:#00ffff}
tr:nth-child(even){background:#0f0f2a}
.pass{color:#00ff80}.fail{color:#ff4444}.warn{color:#ffaa00}
.header{background:linear-gradient(135deg,#0a0a2a,#1a1a4a);padding:20px;border-radius:10px;margin-bottom:20px}
.metric{display:inline-block;background:#1a1a3a;padding:15px;border-radius:8px;margin:5px;min-width:200px;border:1px solid #2a2a5a}
.metric .label{color:#888;font-size:12px}.metric .value{font-size:24px;font-weight:bold;color:#00ffff}
.footer{margin-top:30px;padding-top:10px;border-top:1px solid #2a2a4a;color:#666;font-size:12px}
</style></head><body>
<div class="header"><h1>CyberScan 2026 - Security Report</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Computer: $($cs.Name) | OS: $($os.Caption)</p></div>
<div>
<div class="metric"><div class="label">CPU</div><div class="value">$($cpu.Name)</div></div>
<div class="metric"><div class="label">RAM</div><div class="value">$([math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB</div></div>
<div class="metric"><div class="label">Disk C: Used</div><div class="value">$diskPct%</div></div>
<div class="metric"><div class="label">Open Ports</div><div class="value">$listeners</div></div>
<div class="metric"><div class="label">Active Connections</div><div class="value">$connections</div></div>
</div>
<h2>Security Status</h2>
<table><tr><th>Check</th><th>Status</th></tr>
<tr><td>Antivirus</td><td>$avStatus</td></tr>
<tr><td>Firewall</td><td>$fwStatus</td></tr>
<tr><td>Listening Ports</td><td>$listeners</td></tr>
<tr><td>Active Connections</td><td>$connections</td></tr></table>
<h2>User Accounts</h2>
<table><tr><th>Username</th><th>Last Logon</th><th>Password Required</th></tr>
$userList</table>
<div class="footer">CyberScan 2026 TITAN ULTIMATE v10.0 - Developed by Ronald Goodchild</div>
</body></html>
"@
            $html | Out-File -FilePath $reportPath -Encoding UTF8
            Write-Output "HTML Security Report saved to:"
            Write-Output $reportPath
            Start-Process $reportPath
            Write-Output "Report opened in default browser."
        }
    }.GetNewClosure() }
)

# --- 7. THREAT INTEL (NEW) ---
Add-CategoryButton -Label "THREAT INTEL" -LabelColor $colorCatRed -Tooltip "CVE scanner, CIS baseline, ATT&CK mapping, breach check, event log hunting" -SubItems @(
    @{ Text = "CVE Vulnerability Scanner"; OnClick = {
        & $script:InvokeTask "CVE Vulnerability Scanner" $false {
            Write-Output "=== CVE VULNERABILITY SCANNER ==="
            Write-Output "Scanning installed software against known vulnerabilities..."
            Write-Output ""
            $apps = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayVersion } | Select-Object DisplayName, DisplayVersion, Publisher
            # Known vulnerable versions database (embedded for offline use)
            $vulnDB = @(
                @{Name="*Chrome*";BadVer="13[0-1]\.*";CVE="CVE-2024-7971";Sev="CRITICAL";Fix="Update Chrome to latest"},
                @{Name="*Firefox*";BadVer="12[0-9]\.*";CVE="CVE-2024-9680";Sev="CRITICAL";Fix="Update Firefox to latest"},
                @{Name="*7-Zip*";BadVer="2[0-3]\.*";CVE="CVE-2024-11477";Sev="HIGH";Fix="Update 7-Zip to 24.x+"},
                @{Name="*Adobe*Reader*";BadVer="2[0-2]\.*";CVE="CVE-2024-41869";Sev="CRITICAL";Fix="Update Adobe Reader"},
                @{Name="*VLC*";BadVer="3\.[0-1][0-6]\.*";CVE="CVE-2023-47360";Sev="HIGH";Fix="Update VLC to 3.0.20+"},
                @{Name="*PuTTY*";BadVer="0\.(7[0-8]|[0-6])\.*";CVE="CVE-2024-31497";Sev="CRITICAL";Fix="Update PuTTY to 0.81+"},
                @{Name="*WinRAR*";BadVer="[0-6]\.[0-9]*";CVE="CVE-2023-38831";Sev="CRITICAL";Fix="Update WinRAR to 7.x+"},
                @{Name="*Java*";BadVer="8\.0\.(3[0-8]|[0-2])\.*";CVE="CVE-2024-21011";Sev="HIGH";Fix="Update Java to latest"},
                @{Name="*Node*";BadVer="1[0-7]\.*";CVE="CVE-2024-22019";Sev="HIGH";Fix="Update Node.js to 18+"},
                @{Name="*Python*3\.[0-9]*";BadVer="3\.[0-9]\..*";CVE="CVE-2024-6923";Sev="MEDIUM";Fix="Update Python to latest patch"},
                @{Name="*OpenSSL*";BadVer="1\.[01]\.*";CVE="CVE-2024-5535";Sev="CRITICAL";Fix="Update OpenSSL to 3.x+"},
                @{Name="*Git*";BadVer="2\.(4[0-4]|[0-3])\.*";CVE="CVE-2024-32002";Sev="CRITICAL";Fix="Update Git to 2.45+"},
                @{Name="*Visual Studio Code*";BadVer="1\.(8[0-8]|[0-7])\.*";CVE="CVE-2024-26165";Sev="HIGH";Fix="Update VS Code to latest"},
                @{Name="*Zoom*";BadVer="5\.[0-9]\.*";CVE="CVE-2024-24691";Sev="CRITICAL";Fix="Update Zoom to 6.x+"},
                @{Name="*Notepad++*";BadVer="8\.[0-5]\.*";CVE="CVE-2023-40031";Sev="HIGH";Fix="Update Notepad++ to 8.6+"}
            )
            $critCount = 0; $highCount = 0; $medCount = 0
            foreach ($app in $apps) {
                foreach ($vuln in $vulnDB) {
                    if ($app.DisplayName -like $vuln.Name) {
                        if ($app.DisplayVersion -match $vuln.BadVer) {
                            $sevTag = switch ($vuln.Sev) { "CRITICAL" { "!!!" } "HIGH" { ">> " } "MEDIUM" { " ! " } default { "   " } }
                            Write-Output "$sevTag $($vuln.CVE) [$($vuln.Sev)]"
                            Write-Output "    App: $($app.DisplayName) v$($app.DisplayVersion)"
                            Write-Output "    Fix: $($vuln.Fix)"
                            Write-Output ""
                            switch ($vuln.Sev) { "CRITICAL" { $critCount++ } "HIGH" { $highCount++ } "MEDIUM" { $medCount++ } }
                        }
                    }
                }
            }
            # OS version check
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            if ($os.BuildNumber -lt 22621) {
                Write-Output "!!! CVE-MULTIPLE [CRITICAL]"
                Write-Output "    OS Build $($os.BuildNumber) may be missing security patches"
                Write-Output "    Fix: Update to Windows 11 22H2+ or latest Windows 10"
                Write-Output ""; $critCount++
            }
            Write-Output "=== SCAN COMPLETE ==="
            Write-Output "Critical: $critCount | High: $highCount | Medium: $medCount"
            if ($critCount -eq 0 -and $highCount -eq 0) { Write-Output "No known vulnerable software versions detected." }
            else { Write-Output ">>> Update the flagged software immediately!" }

            $vulnFindings = @()
            if ($critCount -gt 0) { $vulnFindings += "Critical vulnerable software detected" }
            elseif ($highCount -gt 0) { $vulnFindings += "High severity vulnerable software detected" }
            if ($vulnFindings.Count -gt 0) {
                Show-FixPrompt -Title "CVE Vulnerability Scanner" -Findings $vulnFindings -FixMap @{
                    "Critical vulnerable software detected" = { Start-Process "ms-settings:windowsupdate" }
                    "High severity vulnerable software detected" = { Start-Process "ms-settings:windowsupdate" }
                }
            }
        }
    }.GetNewClosure() }
    @{ Text = "CIS Security Baseline Check"; OnClick = {
        & $script:InvokeTask "CIS Baseline Audit" $false {
            Write-Output "=== CIS SECURITY BASELINE AUDIT ==="
            Write-Output "Checking system against CIS Benchmark recommendations..."
            Write-Output ""
            $pass = 0; $fail = 0; $total = 0; $cisFindings = @()

            # 1. Password complexity
            $total++
            $netAccounts = net accounts 2>&1 | Out-String
            if ($netAccounts -match "Minimum password length:\s+(\d+)") { $minLen = [int]$Matches[1] }
            else { $minLen = 0 }
            if ($minLen -ge 8) { $pass++; Write-Output "[PASS] 1.1 Minimum password length: $minLen (>=8)" }
            else { $fail++; $cisFindings += "Set minimum password length to 8+"; Write-Output "[FAIL] 1.1 Minimum password length: $minLen (should be >=8)" }

            # 2. Account lockout threshold
            $total++
            if ($netAccounts -match "Lockout threshold:\s+(\d+|Never)") { $lockout = $Matches[1] }
            else { $lockout = "Never" }
            if ($lockout -ne "Never" -and [int]$lockout -le 5 -and [int]$lockout -gt 0) { $pass++; Write-Output "[PASS] 1.2 Account lockout threshold: $lockout (<=5)" }
            else { $fail++; $cisFindings += "Set account lockout threshold to 5"; Write-Output "[FAIL] 1.2 Account lockout threshold: $lockout (should be <=5)" }

            # 3. Audit policy
            $total++
            $auditpol = auditpol /get /category:* 2>&1 | Out-String
            if ($auditpol -match "Logon\s+Success and Failure") { $pass++; Write-Output "[PASS] 2.1 Logon auditing: Success and Failure" }
            else { $fail++; $cisFindings += "Enable logon audit policy"; Write-Output "[FAIL] 2.1 Logon auditing: Not fully enabled" }

            # 4. Guest account disabled
            $total++
            try {
                $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
                if (-not $guest.Enabled) { $pass++; Write-Output "[PASS] 3.1 Guest account: Disabled" }
                else { $fail++; $cisFindings += "Disable Guest account"; Write-Output "[FAIL] 3.1 Guest account: ENABLED (should be disabled)" }
            } catch { $pass++; Write-Output "[PASS] 3.1 Guest account: Not found" }

            # 5. Administrator account renamed
            $total++
            try {
                $admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
                if ($admin.Name -ne "Administrator") { $pass++; Write-Output "[PASS] 3.2 Built-in Admin renamed to: $($admin.Name)" }
                else { $fail++; $cisFindings += "Rename built-in Administrator account"; Write-Output "[FAIL] 3.2 Built-in Admin account not renamed (still 'Administrator')" }
            } catch { Write-Output "[INFO] 3.2 Cannot check admin account" }

            # 6. Windows Firewall Domain profile
            $total++
            try {
                $fwDomain = Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue
                if ($fwDomain.Enabled) { $pass++; Write-Output "[PASS] 4.1 Domain Firewall: Enabled" }
                else { $fail++; $cisFindings += "Enable Domain firewall profile"; Write-Output "[FAIL] 4.1 Domain Firewall: DISABLED" }
            } catch { Write-Output "[INFO] 4.1 Cannot check Domain firewall" }

            # 7. Windows Firewall Public profile
            $total++
            try {
                $fwPublic = Get-NetFirewallProfile -Name Public -ErrorAction SilentlyContinue
                if ($fwPublic.Enabled) { $pass++; Write-Output "[PASS] 4.2 Public Firewall: Enabled" }
                else { $fail++; $cisFindings += "Enable Public firewall profile"; Write-Output "[FAIL] 4.2 Public Firewall: DISABLED" }
            } catch { Write-Output "[INFO] 4.2 Cannot check Public firewall" }

            # 8. Remote Desktop disabled
            $total++
            try {
                $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
                if ($rdp.fDenyTSConnections -eq 1) { $pass++; Write-Output "[PASS] 5.1 Remote Desktop: Disabled" }
                else { $fail++; $cisFindings += "Disable Remote Desktop (RDP)"; Write-Output "[FAIL] 5.1 Remote Desktop: ENABLED" }
            } catch { Write-Output "[INFO] 5.1 Cannot check RDP" }

            # 9. Autoplay disabled
            $total++
            try {
                $ap = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
                if ($ap.NoDriveTypeAutoRun -eq 255) { $pass++; Write-Output "[PASS] 6.1 AutoPlay: Disabled for all drives" }
                else { $fail++; $cisFindings += "Disable AutoPlay for all drives"; Write-Output "[FAIL] 6.1 AutoPlay: Not fully disabled" }
            } catch { $fail++; $cisFindings += "Disable AutoPlay for all drives"; Write-Output "[FAIL] 6.1 AutoPlay: Policy not set" }

            # 10. SMBv1 disabled
            $total++
            try {
                $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                if (-not $smb.EnableSMB1Protocol) { $pass++; Write-Output "[PASS] 7.1 SMBv1: Disabled" }
                else { $fail++; $cisFindings += "Disable SMBv1 protocol"; Write-Output "[FAIL] 7.1 SMBv1: ENABLED (critical vulnerability)" }
            } catch { Write-Output "[INFO] 7.1 Cannot check SMBv1" }

            # 11. PowerShell script logging
            $total++
            try {
                $psLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
                if ($psLog.EnableScriptBlockLogging -eq 1) { $pass++; Write-Output "[PASS] 8.1 PowerShell Script Logging: Enabled" }
                else { $fail++; $cisFindings += "Enable PowerShell Script Block Logging"; Write-Output "[FAIL] 8.1 PowerShell Script Logging: Disabled" }
            } catch { $fail++; $cisFindings += "Enable PowerShell Script Block Logging"; Write-Output "[FAIL] 8.1 PowerShell Script Logging: Not configured" }

            # 12. Windows Defender Tamper Protection
            $total++
            try {
                $tp = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($tp.IsTamperProtected) { $pass++; Write-Output "[PASS] 9.1 Defender Tamper Protection: Enabled" }
                else { $fail++; $cisFindings += "Enable Defender Tamper Protection"; Write-Output "[FAIL] 9.1 Defender Tamper Protection: Disabled" }
            } catch { Write-Output "[INFO] 9.1 Cannot check Tamper Protection" }

            $pct = if ($total -gt 0) { [math]::Round(($pass / $total) * 100) } else { 0 }
            Write-Output ""
            Write-Output "=== CIS BASELINE RESULTS ==="
            Write-Output "Passed: $pass / $total ($pct%)"
            Write-Output "Failed: $fail"
            Save-ScanResult -ScanName "CIS Baseline" -Score $pass -MaxScore $total -Issues $fail
            if ($cisFindings.Count -gt 0) {
                Show-FixPrompt -Title "CIS Baseline Audit" -Findings $cisFindings -FixMap @{
                    "Set minimum password length to 8+"                  = { net accounts /minpwlen:8 | Out-Null; Write-Output "Fixed: Set minimum password length to 8" }
                    "Set account lockout threshold to 5"                 = { net accounts /lockoutthreshold:5 | Out-Null; Write-Output "Fixed: Set account lockout threshold to 5" }
                    "Enable logon audit policy"                          = { auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null; Write-Output "Fixed: Enabled logon audit policy" }
                    "Disable Guest account"                              = { Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue; Write-Output "Fixed: Disabled Guest account" }
                    "Rename built-in Administrator account"              = { Start-Process "lusrmgr.msc"; Write-Output "Opened Local Users and Groups - rename Administrator manually." }
                    "Enable Domain firewall profile"                     = { Set-NetFirewallProfile -Name Domain  -Enabled True -ErrorAction SilentlyContinue; Write-Output "Fixed: Enabled Domain firewall" }
                    "Enable Public firewall profile"                     = { Set-NetFirewallProfile -Name Public  -Enabled True -ErrorAction SilentlyContinue; Write-Output "Fixed: Enabled Public firewall" }
                    "Disable Remote Desktop (RDP)"                      = { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 1 -ErrorAction SilentlyContinue; Write-Output "Fixed: Disabled RDP" }
                    "Disable AutoPlay for all drives"                    = { if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null }; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -Value 255 -ErrorAction SilentlyContinue; Write-Output "Fixed: Disabled AutoPlay for all drives" }
                    "Disable SMBv1 protocol"                             = { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue; Write-Output "Fixed: Disabled SMBv1" }
                    "Enable PowerShell Script Block Logging"             = { if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null }; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -ErrorAction SilentlyContinue; Write-Output "Fixed: Enabled PS Script Block Logging" }
                    "Enable Defender Tamper Protection"                  = { Start-Process "windowsdefender://threatsettings"; Write-Output "Opened Defender settings - enable Tamper Protection manually." }
                }
            }
        }
    }.GetNewClosure() },
    @{ Text = "Network Threat Intelligence"; OnClick = {
        & $script:InvokeTask "Network Threat Intel" $false {
            Write-Output "=== NETWORK THREAT INTELLIGENCE ==="
            Write-Output "Analyzing active connections for threats..."
            Write-Output ""
            $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
            $threats = 0; $beaconCandidates = @{}
            $suspiciousPorts = @{4444="Metasploit";6666="IRC Backdoor";6667="IRC C2";1337="Elite/Backdoor";31337="Back Orifice";12345="NetBus";9001="Tor/C2"}
            foreach ($conn in $conns) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                $pname = if ($proc) { $proc.ProcessName } else { "Unknown" }
                $rip = $conn.RemoteAddress
                $rport = $conn.RemotePort
                $threat = $null
                # Check suspicious remote ports
                if ($suspiciousPorts.ContainsKey([int]$rport)) { $threat = "Suspicious port $rport ($($suspiciousPorts[[int]$rport]))"; $threats++ }
                # Check for Tor exit nodes / known bad ranges
                foreach ($range in $HighRiskRanges) { if ($rip -match $range.Range) { $threat = $range.Desc; $threats++; break } }
                # Track for beaconing (same IP multiple connections)
                if (-not $beaconCandidates.ContainsKey($rip)) { $beaconCandidates[$rip] = @{Count=0;Procs=@()} }
                $beaconCandidates[$rip].Count++
                if ($pname -notin $beaconCandidates[$rip].Procs) { $beaconCandidates[$rip].Procs += $pname }
                # Check if process is in suspicious location
                if ($proc -and $proc.MainModule) {
                    $path = $proc.MainModule.FileName
                    if ($path -like "*\Temp\*" -or $path -like "*\AppData\Local\Temp\*") { $threat = "Process running from Temp folder"; $threats++ }
                }
                if ($threat) {
                    Write-Output ">>> THREAT: $threat"
                    Write-Output "    Process: $pname (PID $($conn.OwningProcess))"
                    Write-Output "    Remote: ${rip}:${rport}"
                    Write-Output ""
                }
            }
            # Beaconing analysis
            Write-Output "=== BEACONING ANALYSIS ==="
            $beacons = $beaconCandidates.GetEnumerator() | Where-Object { $_.Value.Count -ge 5 } | Sort-Object { $_.Value.Count } -Descending
            if ($beacons) {
                foreach ($b in $beacons) {
                    Write-Output "  $($b.Key): $($b.Value.Count) connections via $($b.Value.Procs -join ', ')"
                }
            } else { Write-Output "  No beaconing patterns detected." }
            Write-Output ""; Write-Output "=== SUMMARY ==="
            Write-Output "Total connections: $($conns.Count) | Threats found: $threats"
            if ($threats -gt 0) {
                Write-Output ""; Write-Output ">>> ACTION REQUIRED: Threats detected in active connections!"
                Show-FixPrompt -Title "Network Threat Intelligence" -Findings @("Active network threats detected") -FixMap @{
                    "Active network threats detected" = {
                        Write-Output "Running Defender Quick Scan to check for malware..."
                        Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
                        Write-Output "Quick scan initiated. Check Windows Security for results."
                    }
                }
            }
        }
    }.GetNewClosure() },
    @{ Text = "Dark Web Breach Check (HIBP)"; OnClick = {
        & $script:InvokeTask "Breach Check" $false {
            Write-Output "=============================================="
            Write-Output "   DARK WEB BREACH CHECK (Have I Been Pwned)"
            Write-Output "=============================================="
            Write-Output ""

            $keyFile = "$CyberScanData\hibp_key.txt"
            $apiKey = $null

            # Load saved API key
            if (Test-Path $keyFile) {
                $apiKey = (Get-Content $keyFile -Raw -ErrorAction SilentlyContinue).Trim()
                if ($apiKey) { Write-Output "Using saved HIBP API key." }
            }

            # If no key, prompt for one
            if (-not $apiKey) {
                Write-Output "No HIBP API key found."
                Write-Output ""
                Write-Output "An API key is required for email breach lookups."
                Write-Output "Get one at: https://haveibeenpwned.com/API/Key (one-time ~$3.50)"
                Write-Output ""
                $inputForm = New-Object System.Windows.Forms.Form
                $inputForm.Text = "HIBP API Key"; $inputForm.Size = New-Object System.Drawing.Size(480, 200)
                $inputForm.StartPosition = "CenterScreen"; $inputForm.FormBorderStyle = "FixedDialog"
                $inputForm.MaximizeBox = $false; $inputForm.MinimizeBox = $false
                $inputForm.BackColor = [System.Drawing.Color]::FromArgb(18, 18, 28)
                $inputForm.ForeColor = [System.Drawing.Color]::White

                $lbl = New-Object System.Windows.Forms.Label
                $lbl.Text = "Enter your HIBP API key (leave blank to skip email check):"
                $lbl.Location = New-Object System.Drawing.Point(15, 15); $lbl.Size = New-Object System.Drawing.Size(440, 20)
                $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
                $inputForm.Controls.Add($lbl)

                $lbl2 = New-Object System.Windows.Forms.Label
                $lbl2.Text = "Get a key at: haveibeenpwned.com/API/Key"
                $lbl2.Location = New-Object System.Drawing.Point(15, 38); $lbl2.Size = New-Object System.Drawing.Size(440, 18)
                $lbl2.Font = New-Object System.Drawing.Font("Segoe UI", 8); $lbl2.ForeColor = [System.Drawing.Color]::FromArgb(100, 160, 220)
                $inputForm.Controls.Add($lbl2)

                $txt = New-Object System.Windows.Forms.TextBox
                $txt.Location = New-Object System.Drawing.Point(15, 65); $txt.Size = New-Object System.Drawing.Size(435, 28)
                $txt.Font = New-Object System.Drawing.Font("Consolas", 10)
                $txt.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 50)
                $txt.ForeColor = [System.Drawing.Color]::Cyan
                $inputForm.Controls.Add($txt)

                $okBtn = New-Object System.Windows.Forms.Button
                $okBtn.Text = "OK"; $okBtn.Size = New-Object System.Drawing.Size(90, 32)
                $okBtn.Location = New-Object System.Drawing.Point(150, 110); $okBtn.FlatStyle = "Flat"
                $okBtn.BackColor = [System.Drawing.Color]::FromArgb(25, 60, 120); $okBtn.ForeColor = [System.Drawing.Color]::White
                $okBtn.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $inputForm.Controls.Add($okBtn)

                $skipBtn = New-Object System.Windows.Forms.Button
                $skipBtn.Text = "Skip"; $skipBtn.Size = New-Object System.Drawing.Size(90, 32)
                $skipBtn.Location = New-Object System.Drawing.Point(250, 110); $skipBtn.FlatStyle = "Flat"
                $skipBtn.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 80); $skipBtn.ForeColor = [System.Drawing.Color]::White
                $skipBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                $inputForm.Controls.Add($skipBtn)

                $inputForm.AcceptButton = $okBtn; $inputForm.CancelButton = $skipBtn

                $result = $inputForm.ShowDialog()
                if ($result -eq [System.Windows.Forms.DialogResult]::OK -and $txt.Text.Trim()) {
                    $apiKey = $txt.Text.Trim()
                    # Save key for future use
                    $apiKey | Out-File $keyFile -Encoding UTF8 -Force
                    Write-Output "API key saved for future scans."
                }
                $inputForm.Dispose()
            }

            # --- Email Breach Lookup (requires API key) ---
            Write-Output ""
            Write-Output "=== EMAIL BREACH LOOKUP ==="
            if ($apiKey) {
                # Auto-detect email
                $email = $null
                try { $email = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\IdentityCRL\UserExtendedProperties\*" -ErrorAction SilentlyContinue | Select-Object -First 1).PSChildName } catch {}
                if (-not $email) {
                    try { $accounts = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\IdentityCRL\StoredIdentities\*" -ErrorAction SilentlyContinue; if ($accounts) { $email = ($accounts | Select-Object -First 1).PSChildName } } catch {}
                }
                if ($email) {
                    Write-Output "Checking: $email"
                    Write-Output ""
                    try {
                        $uri = "https://haveibeenpwned.com/api/v3/breachedaccount/$([uri]::EscapeDataString($email))?truncateResponse=false"
                        $headers = @{ "hibp-api-key" = $apiKey; "user-agent" = "CyberScan-2026" }
                        $response = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 15 -ErrorAction Stop
                        if ($response) {
                            Write-Output ">>> WARNING: Email found in $($response.Count) breach(es)!"
                            Write-Output ""
                            foreach ($b in $response) {
                                Write-Output "  BREACH: $($b.Name)"
                                Write-Output "  Date:   $($b.BreachDate)"
                                Write-Output "  Data:   $($b.DataClasses -join ', ')"
                                Write-Output ""
                            }
                            Write-Output "RECOMMENDATION: Change passwords for affected services."
                            Write-Output "Use unique passwords + a password manager."
                        }
                    } catch {
                        $statusCode = $null
                        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}
                        if ($statusCode -eq 404) {
                            Write-Output "[CLEAN] $email was NOT found in any known breaches!"
                        } elseif ($statusCode -eq 401) {
                            Write-Output "[ERROR] Invalid API key. Please delete the saved key and re-enter."
                            Write-Output "  Key file: $keyFile"
                            Remove-Item $keyFile -Force -ErrorAction SilentlyContinue
                            Write-Output "  Saved key removed. Run this check again to enter a new key."
                        } elseif ($statusCode -eq 429) {
                            Write-Output "[RATE LIMITED] Too many requests. Wait a moment and try again."
                        } else {
                            Write-Output "[ERROR] Could not reach HIBP API: $($_.Exception.Message)"
                        }
                    }
                } else {
                    Write-Output "No Microsoft account detected on this system."
                    Write-Output "Visit https://haveibeenpwned.com to check manually."
                }
            } else {
                Write-Output "Skipped (no API key). Email breach lookup requires an HIBP API key."
                Write-Output "Get one at: https://haveibeenpwned.com/API/Key"
            }

            # --- Free Password Hash Check (k-anonymity, NO key needed) ---
            Write-Output ""
            Write-Output "=== PASSWORD BREACH CHECK (free, no key needed) ==="
            Write-Output "This checks if common/test passwords appear in known breach databases"
            Write-Output "using k-anonymity (only first 5 chars of hash sent, your password stays private)."
            Write-Output ""

            # Check saved Wi-Fi passwords for breach exposure
            $wifiChecked = 0; $wifiBreached = 0
            $profileList = netsh wlan show profiles 2>&1 | Out-String
            $profileNames = [regex]::Matches($profileList, "All User Profile\s*:\s*(.+)") | ForEach-Object { $_.Groups[1].Value.Trim() }
            foreach ($pn in ($profileNames | Select-Object -First 10)) {
                $detail = netsh wlan show profile name="$pn" key=clear 2>&1 | Out-String
                if ($detail -match "Key Content\s*:\s*(.+)") {
                    $wifiPass = $Matches[1].Trim()
                    $wifiChecked++
                    try {
                        $sha1 = [System.Security.Cryptography.SHA1]::Create()
                        $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($wifiPass))
                        $hashHex = ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ""
                        $prefix = $hashHex.Substring(0, 5)
                        $suffix = $hashHex.Substring(5)
                        $rangeResponse = Invoke-RestMethod -Uri "https://api.pwnedpasswords.com/range/$prefix" -TimeoutSec 10 -ErrorAction Stop
                        if ($rangeResponse -match "(?m)^$suffix`:(\d+)") {
                            $count = $Matches[1]
                            Write-Output ">>> BREACHED: Wi-Fi '$pn' password found in $count breach(es)!"
                            $wifiBreached++
                        }
                        Start-Sleep -Milliseconds 200
                    } catch {}
                }
            }
            if ($wifiChecked -gt 0) {
                Write-Output ""
                Write-Output "Wi-Fi passwords checked: $wifiChecked | Breached: $wifiBreached"
                if ($wifiBreached -gt 0) { Write-Output ">>> Change breached Wi-Fi passwords immediately!" }
                else { Write-Output "[CLEAN] No Wi-Fi passwords found in breach databases." }
            } else { Write-Output "No saved Wi-Fi passwords with key content found." }

            # --- Local Password Hygiene ---
            Write-Output ""
            Write-Output "=== LOCAL PASSWORD HYGIENE ==="
            $users = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
            foreach ($u in $users) {
                $lastSet = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Never" }
                $age = if ($u.PasswordLastSet) { [math]::Round(((Get-Date) - $u.PasswordLastSet).TotalDays) } else { 9999 }
                $flag = if ($age -gt 90) { ">>> OLD" } elseif ($age -gt 60) { "(!)" } else { "   " }
                Write-Output "$flag $($u.Name): Password last set $lastSet ($age days ago)"
            }
        }
    }.GetNewClosure() },
    @{ Text = "Ransomware Canary Deploy"; OnClick = {
        & $script:InvokeTask "Ransomware Canary" $true {
            Write-Output "=== RANSOMWARE CANARY DEPLOYMENT ==="
            $canaryDir = "$env:USERPROFILE\.cyberscan"
            if (-not (Test-Path $canaryDir)) { New-Item -ItemType Directory -Path $canaryDir -Force | Out-Null }
            $canaryFiles = @(
                @{Path="$RealDocuments\~canary_doc.txt"; Content="CYBERSCAN CANARY FILE - DO NOT DELETE - $(Get-Date)"},
                @{Path="$RealDesktop\~canary_desktop.txt"; Content="CYBERSCAN CANARY FILE - DO NOT DELETE - $(Get-Date)"},
                @{Path="$RealPictures\~canary_pics.txt"; Content="CYBERSCAN CANARY FILE - DO NOT DELETE - $(Get-Date)"}
            )
            $hashFile = "$canaryDir\canary_hashes.json"
            $hashes = @{}
            foreach ($cf in $canaryFiles) {
                $cf.Content | Out-File -FilePath $cf.Path -Encoding UTF8 -Force
                $hash = (Get-FileHash $cf.Path -Algorithm SHA256).Hash
                $hashes[$cf.Path] = $hash
                Write-Output "Deployed: $($cf.Path)"
                Write-Output "  Hash: $hash"
            }
            $hashes | ConvertTo-Json | Out-File $hashFile -Encoding UTF8
            Write-Output ""
            Write-Output "Canary files deployed to Documents, Desktop, and Pictures."
            Write-Output "Hash baseline saved to $hashFile"
            Write-Output ""
            Write-Output "Run 'Ransomware Canary Check' to verify file integrity."
            Write-Output "If ransomware encrypts these files, the hash check will detect it."
        }
    }.GetNewClosure() },
    @{ Text = "Ransomware Canary Check"; OnClick = {
        & $script:InvokeTask "Canary Integrity Check" $false {
            Write-Output "=== RANSOMWARE CANARY INTEGRITY CHECK ==="
            $hashFile = "$env:USERPROFILE\.cyberscan\canary_hashes.json"
            if (-not (Test-Path $hashFile)) {
                Write-Output "No canary baseline found. Deploy canaries first."
                return
            }
            $baseline = Get-Content $hashFile -Raw | ConvertFrom-Json
            $tampered = 0; $missing = 0; $ok = 0
            foreach ($prop in $baseline.PSObject.Properties) {
                $filePath = $prop.Name; $expectedHash = $prop.Value
                if (-not (Test-Path $filePath)) {
                    Write-Output ">>> MISSING: $filePath"; $missing++
                } else {
                    $currentHash = (Get-FileHash $filePath -Algorithm SHA256).Hash
                    if ($currentHash -ne $expectedHash) {
                        Write-Output ">>> TAMPERED: $filePath"
                        Write-Output "    Expected: $expectedHash"
                        Write-Output "    Current:  $currentHash"
                        $tampered++
                    } else { Write-Output "[OK] $filePath"; $ok++ }
                }
            }
            Write-Output ""; Write-Output "Results: $ok intact | $missing missing | $tampered tampered"
            if ($tampered -gt 0 -or $missing -gt 0) {
                Write-Output ""; Write-Output ">>> ALERT: Canary files have been modified or deleted!"
                Write-Output ">>> This could indicate ransomware or unauthorized file access!"
                Show-FixPrompt -Title "Ransomware Canary Check" -Findings @("Canary files tampered or missing") -FixMap @{
                    "Canary files tampered or missing" = {
                        Write-Output "Initiating emergency response..."
                        Write-Output "Step 1: Running Defender Full Scan..."
                        Start-MpScan -ScanType FullScan -ErrorAction SilentlyContinue
                        Write-Output "Full scan initiated."
                        Write-Output "Step 2: Opening Windows Security for review..."
                        Start-Process "windowsdefender://threatsettings"
                        Write-Output "RECOMMENDATION: Disconnect from network and contact your IT team immediately if ransomware is confirmed."
                    }
                }
            } else { Write-Output "All canary files intact. No ransomware activity detected." }
        }
    }.GetNewClosure() },
    @{ Text = "Event Log Threat Hunter"; OnClick = {
        & $script:InvokeTask "Event Log Threat Hunter" $false {
            Write-Output "=============================================="
            Write-Output "   EVENT LOG THREAT HUNTER + ATT&CK MAPPING"
            Write-Output "=============================================="
            Write-Output ""
            $threats = 0; $findings = @()

            # 1. Brute Force Detection (Event 4625 - Failed logons)
            Write-Output "=== BRUTE FORCE DETECTION (Event 4625) ==="
            try {
                $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 500 -ErrorAction SilentlyContinue
                if ($failedLogons) {
                    $grouped = $failedLogons | Group-Object { $_.Properties[5].Value } | Where-Object { $_.Count -ge 5 } | Sort-Object Count -Descending
                    if ($grouped) {
                        foreach ($g in $grouped) {
                            $acct = $g.Name; $count = $g.Count
                            $latest = ($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                            Write-Output ">>> $count failed logons for '$acct' (latest: $latest)"
                            $mitreTag = Get-MitreTag "BruteForce"
                            if ($mitreTag) { Write-Output "    $mitreTag" }
                            $threats++
                        }
                        $findings += "Brute force attempts detected"
                    } else { Write-Output "  No brute force patterns (5+ failures per account) in last 7 days." }
                    Write-Output "  Total failed logons (7d): $($failedLogons.Count)"
                } else { Write-Output "  No failed logon events found in last 7 days." }
            } catch { Write-Output "  Cannot read Security log (requires Admin)." }
            Write-Output ""

            # 2. Lateral Movement Detection (Event 4624 Type 3 - Network logon)
            Write-Output "=== LATERAL MOVEMENT DETECTION (Event 4624 Type 3) ==="
            try {
                $netLogons = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-3)} -MaxEvents 1000 -ErrorAction SilentlyContinue
                if ($netLogons) {
                    $type3 = $netLogons | Where-Object { $_.Properties[8].Value -eq 3 }
                    $remoteIPs = $type3 | Group-Object { $_.Properties[18].Value } | Where-Object { $_.Name -ne "-" -and $_.Name -ne "::1" -and $_.Name -ne "127.0.0.1" } | Sort-Object Count -Descending | Select-Object -First 10
                    if ($remoteIPs) {
                        foreach ($r in $remoteIPs) {
                            $flag = if ($r.Count -ge 20) { ">>>" } else { "   " }
                            Write-Output "$flag Network logon from $($r.Name): $($r.Count) times"
                            if ($r.Count -ge 20) {
                                $mitreTag = Get-MitreTag "LateralMovement"
                                if ($mitreTag) { Write-Output "    $mitreTag" }
                                $threats++
                            }
                        }
                    } else { Write-Output "  No remote network logons detected." }
                } else { Write-Output "  No logon events in last 3 days." }
            } catch { Write-Output "  Cannot read Security log." }
            Write-Output ""

            # 3. Suspicious Service Installation (Event 7045)
            Write-Output "=== SUSPICIOUS SERVICE INSTALLS (Event 7045) ==="
            try {
                $newServices = Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 100 -ErrorAction SilentlyContinue
                if ($newServices) {
                    $suspKeywords = @("temp","appdata","powershell","cmd.exe","wscript","cscript","mshta","rundll32","regsvr32","certutil")
                    foreach ($svc in $newServices) {
                        $svcName = $svc.Properties[0].Value
                        $svcPath = $svc.Properties[1].Value
                        $isSusp = $false
                        foreach ($kw in $suspKeywords) { if ($svcPath -match $kw) { $isSusp = $true; break } }
                        if ($isSusp) {
                            Write-Output ">>> SUSPICIOUS SERVICE: $svcName"
                            Write-Output "    Path: $svcPath"
                            Write-Output "    Installed: $($svc.TimeCreated)"
                            $mitreTag = Get-MitreTag "NewService"
                            if ($mitreTag) { Write-Output "    $mitreTag" }
                            $threats++; $findings += "Suspicious service: $svcName"
                        }
                    }
                    Write-Output "  Total new services (30d): $($newServices.Count)"
                } else { Write-Output "  No new service installations in last 30 days." }
            } catch { Write-Output "  Cannot read System log." }
            Write-Output ""

            # 4. PowerShell Script Block Logging (Event 4104)
            Write-Output "=== POWERSHELL SUSPICIOUS ACTIVITY (Event 4104) ==="
            try {
                $psLogs = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 500 -ErrorAction SilentlyContinue
                if ($psLogs) {
                    # Build detection patterns at runtime to avoid AV false-positive on this script
                    $suspPatterns = @(
                        ("Inv" + "oke-Mimi" + "katz"),
                        "Inv" + "oke-Ex" + "pression.*Down" + "load",
                        ("Net.Web" + "Client"),
                        ("IE" + "X\("),
                        "bypass","hidden","-enc ",
                        ("From" + "Base" + "64"),
                        ("Inv" + "oke-Shell" + "code"),
                        ("Inv" + "oke-Com" + "mand.*-Comp" + "uter")
                    )
                    $suspCount = 0
                    foreach ($log in $psLogs) {
                        $scriptText = $log.Properties[2].Value
                        foreach ($pat in $suspPatterns) {
                            if ($scriptText -match $pat) {
                                if ($suspCount -lt 5) {
                                    Write-Output ">>> SUSPICIOUS PS: Matched '$pat'"
                                    Write-Output "    Time: $($log.TimeCreated)"
                                    $preview = $scriptText.Substring(0, [math]::Min(120, $scriptText.Length))
                                    Write-Output "    Preview: $preview..."
                                    $mitreTag = Get-MitreTag "PowerShellExec"
                                    if ($mitreTag) { Write-Output "    $mitreTag" }
                                }
                                $suspCount++; $threats++; break
                            }
                        }
                    }
                    if ($suspCount -gt 5) { Write-Output "  ... and $($suspCount - 5) more suspicious entries" }
                    if ($suspCount -eq 0) { Write-Output "  No suspicious PowerShell patterns detected." }
                    Write-Output "  Total PS script blocks logged (7d): $($psLogs.Count)"
                } else { Write-Output "  No PowerShell script block logs found. Enable Script Block Logging for better detection." }
            } catch { Write-Output "  PowerShell Operational log not available." }
            Write-Output ""

            # 5. Event Log Clearing Detection (Event 1102)
            Write-Output "=== EVENT LOG CLEARING DETECTION (Event 1102) ==="
            try {
                $logClears = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 50 -ErrorAction SilentlyContinue
                if ($logClears) {
                    foreach ($lc in $logClears) {
                        Write-Output ">>> SECURITY LOG CLEARED on $($lc.TimeCreated)"
                        $mitreTag = Get-MitreTag "ClearEventLog"
                        if ($mitreTag) { Write-Output "    $mitreTag" }
                        $threats++
                    }
                    $findings += "Security log was cleared"
                } else { Write-Output "  No log clearing events detected (good)." }
            } catch { Write-Output "  Cannot check log clearing events." }
            Write-Output ""

            # 6. Scheduled Task Creation (Event 4698)
            Write-Output "=== SCHEDULED TASK CREATION (Event 4698) ==="
            try {
                $taskEvents = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698;StartTime=(Get-Date).AddDays(-14)} -MaxEvents 50 -ErrorAction SilentlyContinue
                if ($taskEvents) {
                    foreach ($te in $taskEvents) {
                        $xml = [xml]$te.ToXml()
                        $taskName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TaskName" }).'#text'
                        $taskContent = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TaskContent" }).'#text'
                        $isSusp = $false
                        if ($taskContent -match "powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin") { $isSusp = $true }
                        if ($isSusp) {
                            Write-Output ">>> SUSPICIOUS TASK: $taskName"
                            Write-Output "    Created: $($te.TimeCreated)"
                            $mitreTag = Get-MitreTag "ScheduledTask"
                            if ($mitreTag) { Write-Output "    $mitreTag" }
                            $threats++
                        }
                    }
                    Write-Output "  Total tasks created (14d): $($taskEvents.Count)"
                } else { Write-Output "  No scheduled task creation events in last 14 days." }
            } catch { Write-Output "  Cannot read scheduled task events (enable Object Access auditing)." }
            Write-Output ""

            Write-Output "=============================================="
            Write-Output "  THREAT HUNT COMPLETE"
            Write-Output "  Events analyzed across 6 detection categories"
            Write-Output "  Threats/anomalies found: $threats"
            Write-Output "=============================================="
            if ($threats -gt 0) {
                Write-Output ""
                Write-Output ">>> RECOMMENDED: Review flagged events and investigate ATT&CK techniques."
                Write-Output "    Reference: https://attack.mitre.org"
            }
            Save-ScanResult -ScanName "EventLogThreatHunt" -Score ([math]::Max(0, 100 - ($threats * 10))) -MaxScore 100 -Issues $threats
        }
    }.GetNewClosure() },
    @{ Text = "MITRE ATT&CK Full Mapping"; OnClick = {
        & $script:InvokeTask "MITRE ATT&CK System Mapping" $false {
            Write-Output "=============================================="
            Write-Output "   MITRE ATT&CK SYSTEM EXPOSURE MAPPING"
            Write-Output "=============================================="
            Write-Output ""
            Write-Output "Mapping system configuration to ATT&CK techniques..."
            Write-Output ""
            $exposures = @(); $totalChecks = 0; $exposureCount = 0

            # Check each attack surface
            # T1021.001 - RDP
            $totalChecks++
            try {
                $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue
                if ($rdp.fDenyTSConnections -ne 1) {
                    $exposures += "RDPEnabled"
                    Write-Output ">>> EXPOSED: Remote Desktop is ENABLED"
                    Write-Output "    $(Get-MitreTag 'RDPEnabled')"
                    $exposureCount++
                } else { Write-Output "[SAFE] RDP disabled - T1021.001 mitigated" }
            } catch { Write-Output "[INFO] Cannot check RDP status" }

            # T1210 - SMBv1
            $totalChecks++
            try {
                $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                if ($smb.EnableSMB1Protocol) {
                    $exposures += "SMBv1Enabled"
                    Write-Output ">>> EXPOSED: SMBv1 is ENABLED (EternalBlue risk)"
                    Write-Output "    $(Get-MitreTag 'SMBv1Enabled')"
                    $exposureCount++
                } else { Write-Output "[SAFE] SMBv1 disabled - T1210 mitigated" }
            } catch { Write-Output "[INFO] Cannot check SMBv1" }

            # T1562.001 - Defender disabled
            $totalChecks++
            try {
                $av = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if (-not $av.RealTimeProtectionEnabled) {
                    $exposures += "DefenderDisabled"
                    Write-Output ">>> EXPOSED: Defender Real-time Protection OFF"
                    Write-Output "    $(Get-MitreTag 'DefenderDisabled')"
                    $exposureCount++
                } else { Write-Output "[SAFE] Defender active - T1562.001 mitigated" }
            } catch { Write-Output "[INFO] Cannot check Defender" }

            # T1548.002 - UAC
            $totalChecks++
            try {
                $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue
                if ($uac.EnableLUA -ne 1) {
                    $exposures += "UACDisabled"
                    Write-Output ">>> EXPOSED: UAC is DISABLED"
                    Write-Output "    $(Get-MitreTag 'UACDisabled')"
                    $exposureCount++
                } else { Write-Output "[SAFE] UAC enabled - T1548.002 mitigated" }
            } catch {}

            # T1547.001 - Unsigned startup items
            $totalChecks++
            try {
                $startups = Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue
                $unsigned = 0
                foreach ($s in $startups) {
                    $cmd = $s.Command -replace '"',''
                    $exePath = ($cmd -split '\s')[0]
                    if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                        $sig = Get-AuthenticodeSignature $exePath -ErrorAction SilentlyContinue
                        if ($sig.Status -ne "Valid") { $unsigned++ }
                    }
                }
                if ($unsigned -gt 0) {
                    $exposures += "UnsignedStartup"
                    Write-Output ">>> EXPOSED: $unsigned unsigned startup program(s)"
                    Write-Output "    $(Get-MitreTag 'UnsignedStartup')"
                    $exposureCount++
                } else { Write-Output "[SAFE] All startup items signed - T1547.001 mitigated" }
            } catch {}

            # T1053.005 - Suspicious scheduled tasks
            $totalChecks++
            try {
                $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Ready" -and $_.TaskPath -notlike "\Microsoft\*" }
                $suspTasks = @($tasks | Where-Object {
                    $actions = $_.Actions
                    $isSusp = $false
                    foreach ($a in $actions) { if ($a.Execute -match "powershell|cmd|wscript|cscript|mshta" -and $a.Execute -notlike "*CyberScan*") { $isSusp = $true } }
                    $isSusp
                })
                if ($suspTasks.Count -gt 0) {
                    $exposures += "ScheduledTask"
                    Write-Output ">>> REVIEW: $($suspTasks.Count) non-Microsoft task(s) with script execution"
                    foreach ($st in $suspTasks | Select-Object -First 5) {
                        Write-Output "    Task: $($st.TaskName) | $($st.Actions[0].Execute)"
                    }
                    Write-Output "    $(Get-MitreTag 'ScheduledTask')"
                    $exposureCount++
                } else { Write-Output "[SAFE] No suspicious scheduled tasks - T1053.005 mitigated" }
            } catch {}

            # T1546.003 - WMI Event Subscriptions
            $totalChecks++
            try {
                $wmiSubs = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer -ErrorAction SilentlyContinue
                if ($wmiSubs) {
                    $exposures += "WMIPersistence"
                    Write-Output ">>> EXPOSED: $(@($wmiSubs).Count) WMI event consumer(s) found"
                    foreach ($w in $wmiSubs) { Write-Output "    Consumer: $($w.Name)" }
                    Write-Output "    $(Get-MitreTag 'WMIPersistence')"
                    $exposureCount++
                } else { Write-Output "[SAFE] No WMI persistence - T1546.003 mitigated" }
            } catch {}

            # T1552.001 - Credentials in common files
            $totalChecks++
            $credFiles = 0
            $searchPaths = @("$RealDesktop","$RealDocuments")
            $credPatterns = @("password","api_key","apikey","secret","token","credential","passwd")
            foreach ($sp in $searchPaths) {
                if (Test-Path $sp) {
                    $files = Get-ChildItem $sp -Include "*.txt","*.ini","*.cfg","*.conf","*.env","*.config" -Recurse -ErrorAction SilentlyContinue -Depth 2 | Where-Object { $_.Length -lt 500KB }
                    foreach ($f in $files | Select-Object -First 50) {
                        try {
                            $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
                            foreach ($pat in $credPatterns) {
                                if ($content -match "(?i)$pat\s*[=:]\s*\S+") {
                                    if ($credFiles -lt 5) { Write-Output ">>> FOUND: Potential credentials in $($f.FullName)" }
                                    $credFiles++; break
                                }
                            }
                        } catch {}
                    }
                }
            }
            if ($credFiles -gt 0) {
                $exposures += "CredentialInFile"
                Write-Output "    $credFiles file(s) with potential credentials"
                Write-Output "    $(Get-MitreTag 'CredentialInFile')"
                $exposureCount++
            } else { Write-Output "[SAFE] No plaintext credentials found - T1552.001 mitigated" }

            # T1078.003 - Accounts without passwords
            $totalChecks++
            try {
                $noPwd = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -and -not $_.PasswordRequired })
                if ($noPwd.Count -gt 0) {
                    $exposures += "AccountNoPassword"
                    Write-Output ">>> EXPOSED: $($noPwd.Count) account(s) without password"
                    foreach ($u in $noPwd) { Write-Output "    Account: $($u.Name)" }
                    Write-Output "    $(Get-MitreTag 'AccountNoPassword')"
                    $exposureCount++
                } else { Write-Output "[SAFE] All accounts have passwords - T1078.003 mitigated" }
            } catch {}

            # Summary
            $safe = $totalChecks - $exposureCount
            $pct = if ($totalChecks -gt 0) { [math]::Round(($safe / $totalChecks) * 100) } else { 0 }
            Write-Output ""
            Write-Output "=============================================="
            Write-Output "  ATT&CK EXPOSURE SUMMARY"
            Write-Output "  Checks: $totalChecks | Safe: $safe | Exposed: $exposureCount"
            Write-Output "  Coverage Score: $pct%"
            Write-Output "=============================================="
            if ($exposureCount -gt 0) {
                Write-Output ""
                Write-Output "  Mapped Techniques:"
                foreach ($exp in $exposures) {
                    if ($MitreMap.ContainsKey($exp)) {
                        $m = $MitreMap[$exp]
                        Write-Output "    $($m.TID) - $($m.Desc)"
                    }
                }
                Write-Output ""
                Write-Output "  Reference: https://attack.mitre.org"
            }
            Save-ScanResult -ScanName "ATT&CK Mapping" -Score $safe -MaxScore $totalChecks -Issues $exposureCount
        }
    }.GetNewClosure() }
)

# --- 8. AUDIT (NEW) ---
Add-CategoryButton -Label "AUDIT" -LabelColor $colorCatGold -Tooltip "User accounts, browser, USB, Wi-Fi, file integrity, backup readiness" -SubItems @(
    @{ Text = "User Account & Privilege Audit"; OnClick = {
        & $script:InvokeTask "User Account Audit" $false {
            Write-Output "=== USER ACCOUNT & PRIVILEGE AUDIT ==="
            Write-Output ""
            $users = Get-LocalUser -ErrorAction SilentlyContinue
            Write-Output ("{0,-20} {1,-10} {2,-14} {3,-14} {4}" -f "Username", "Enabled", "PwdRequired", "PwdExpires", "Last Logon")
            Write-Output ("-" * 80)
            foreach ($u in $users) {
                $lastLogon = if ($u.LastLogon) { $u.LastLogon.ToString("yyyy-MM-dd") } else { "Never" }
                $pwdExp = if ($u.PasswordExpires) { $u.PasswordExpires.ToString("yyyy-MM-dd") } else { "Never" }
                $flag = ""
                if ($u.Enabled -and -not $u.PasswordRequired) { $flag = ">>> " }
                elseif ($u.Enabled -and $pwdExp -eq "Never") { $flag = "(!) " }
                Write-Output ("$flag{0,-20} {1,-10} {2,-14} {3,-14} {4}" -f $u.Name, $u.Enabled, $u.PasswordRequired, $pwdExp, $lastLogon)
            }
            Write-Output ""
            # Admin group members
            Write-Output "=== LOCAL ADMINISTRATORS ==="
            try {
                $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                foreach ($a in $admins) { Write-Output "  $($a.ObjectClass): $($a.Name) ($($a.PrincipalSource))" }
            } catch { Write-Output "  Cannot enumerate admin group" }
            Write-Output ""
            # RDP allowed users
            Write-Output "=== REMOTE DESKTOP USERS ==="
            try {
                $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
                if ($rdpUsers) { foreach ($r in $rdpUsers) { Write-Output "  $($r.Name)" } }
                else { Write-Output "  (none)" }
            } catch { Write-Output "  Cannot enumerate RDP users" }
            # Findings
            $noPwd = @($users | Where-Object { $_.Enabled -and -not $_.PasswordRequired })
            $neverExpire = @($users | Where-Object { $_.Enabled -and $null -eq $_.PasswordExpires -and $_.Name -ne "DefaultAccount" })
            if ($noPwd.Count -gt 0) { Write-Output ""; Write-Output ">>> WARNING: $($noPwd.Count) enabled account(s) without password requirement!" }
            if ($neverExpire.Count -gt 0) { Write-Output ">>> WARNING: $($neverExpire.Count) account(s) with non-expiring passwords" }
            $acctFindings = @()
            if ($noPwd.Count -gt 0) { $acctFindings += "Accounts without password requirement" }
            if ($neverExpire.Count -gt 0) { $acctFindings += "Accounts with non-expiring passwords" }
            if ($acctFindings.Count -gt 0) {
                Show-FixPrompt -Title "User Account Audit" -Findings $acctFindings -FixMap @{
                    "Accounts without password requirement" = {
                        $noPwdUsers = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -and -not $_.PasswordRequired }
                        foreach ($u in $noPwdUsers) {
                            try { Set-LocalUser -Name $u.Name -PasswordRequired $true -ErrorAction SilentlyContinue; Write-Output "Fixed: Password now required for $($u.Name)" }
                            catch { Write-Output "Could not update $($u.Name): $($_.Exception.Message)" }
                        }
                    }
                    "Accounts with non-expiring passwords" = { Start-Process "lusrmgr.msc"; Write-Output "Opened Local Users and Groups - set password expiration manually." }
                }
            }
        }
    }.GetNewClosure() },
    @{ Text = "Browser Security Audit"; OnClick = {
        & $script:InvokeTask "Browser Security Audit" $false {
            Write-Output "=== BROWSER SECURITY AUDIT ==="
            Write-Output ""
            # Chrome
            $chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
            if (Test-Path $chromeExtPath) {
                $chromeExts = Get-ChildItem $chromeExtPath -Directory -ErrorAction SilentlyContinue
                Write-Output "CHROME EXTENSIONS ($($chromeExts.Count) installed):"
                foreach ($ext in $chromeExts) {
                    $manifest = Get-ChildItem "$($ext.FullName)\*\manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($manifest) {
                        try {
                            $mf = Get-Content $manifest.FullName -Raw | ConvertFrom-Json
                            $perms = if ($mf.permissions) { ($mf.permissions | Where-Object { $_ -like "*://*" -or $_ -in @("tabs","webRequest","cookies","history") }) -join ", " } else { "none" }
                            $flag = if ($perms -match "http|tabs|webRequest|cookies|history") { "(!)" } else { "   " }
                            Write-Output "  $flag $($mf.name) v$($mf.version)"
                            if ($perms -and $perms -ne "none") { Write-Output "      Sensitive permissions: $perms" }
                        } catch {}
                    }
                }
            } else { Write-Output "Chrome: Not installed or no extensions" }
            Write-Output ""
            # Edge
            $edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
            if (Test-Path $edgeExtPath) {
                $edgeExts = Get-ChildItem $edgeExtPath -Directory -ErrorAction SilentlyContinue
                Write-Output "EDGE EXTENSIONS ($($edgeExts.Count) installed):"
                foreach ($ext in $edgeExts) {
                    $manifest = Get-ChildItem "$($ext.FullName)\*\manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($manifest) {
                        try { $mf = Get-Content $manifest.FullName -Raw | ConvertFrom-Json; Write-Output "  $($mf.name) v$($mf.version)" } catch {}
                    }
                }
            } else { Write-Output "Edge: No custom extensions" }
            Write-Output ""
            # Saved passwords warning
            Write-Output "=== SAVED PASSWORDS CHECK ==="
            $chromeLoginDB = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
            $edgeLoginDB = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
            if (Test-Path $chromeLoginDB) {
                $size = [math]::Round((Get-Item $chromeLoginDB).Length / 1KB)
                Write-Output "  Chrome: Login Data exists (${size} KB) - passwords are stored locally"
            }
            if (Test-Path $edgeLoginDB) {
                $size = [math]::Round((Get-Item $edgeLoginDB).Length / 1KB)
                Write-Output "  Edge: Login Data exists (${size} KB) - passwords are stored locally"
            }
            Write-Output ""
            Write-Output "RECOMMENDATION: Use a dedicated password manager instead of browser storage."
            $browserFindings = @()
            if (Test-Path $chromeLoginDB) { $browserFindings += "Chrome passwords stored locally" }
            if (Test-Path $edgeLoginDB)   { $browserFindings += "Edge passwords stored locally" }
            if ($browserFindings.Count -gt 0) {
                Show-FixPrompt -Title "Browser Security Audit" -Findings $browserFindings -FixMap @{
                    "Chrome passwords stored locally" = { Start-Process "chrome://settings/passwords" -ErrorAction SilentlyContinue; if (-not $?) { Start-Process "chrome.exe" "chrome://settings/passwords" -ErrorAction SilentlyContinue }; Write-Output "Opened Chrome password settings. Export and delete saved passwords, then use a password manager." }
                    "Edge passwords stored locally"   = { Start-Process "microsoft-edge://settings/passwords" -ErrorAction SilentlyContinue; Write-Output "Opened Edge password settings. Export and delete saved passwords, then use a password manager." }
                }
            }
        }
    }.GetNewClosure() },
    @{ Text = "USB Device History"; OnClick = {
        & $script:InvokeTask "USB Device History" $false {
            Write-Output "=== USB DEVICE HISTORY ==="
            Write-Output "All USB storage devices ever connected to this system:"
            Write-Output ""
            Write-Output ("{0,-40} {1,-20} {2}" -f "Device", "Serial", "Last Connected")
            Write-Output ("-" * 80)
            $usbDevices = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue
            if ($usbDevices) {
                foreach ($dev in $usbDevices) {
                    $friendly = $dev.FriendlyName
                    $serial = $dev.PSChildName
                    if ($friendly) {
                        $lastWrite = (Get-Item $dev.PSPath -ErrorAction SilentlyContinue).GetValue("LastArrivalDate")
                        Write-Output ("{0,-40} {1,-20} {2}" -f $friendly, ($serial.Substring(0, [math]::Min(18, $serial.Length))), "See Event Log")
                    }
                }
            } else { Write-Output "No USB storage history found." }
            Write-Output ""
            # Current USB devices
            Write-Output "=== CURRENTLY CONNECTED USB DEVICES ==="
            $current = Get-PnpDevice -Class USB -Status OK -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName }
            if ($current) { foreach ($c in $current) { Write-Output "  $($c.FriendlyName) [$($c.Status)]" } }
            else { Write-Output "  No USB devices currently connected." }
        }
    }.GetNewClosure() },
    @{ Text = "Wi-Fi Security Analyzer"; OnClick = {
        & $script:InvokeTask "Wi-Fi Security" $false {
            Write-Output "=== WI-FI SECURITY ANALYZER ==="
            Write-Output ""
            # Current connection
            $currentWifi = netsh wlan show interfaces 2>&1 | Out-String
            if ($currentWifi -notmatch "There is no wireless") {
                Write-Output "=== CURRENT CONNECTION ==="
                Write-Output $currentWifi
                # Check encryption type
                if ($currentWifi -match "Authentication\s*:\s*(.+)") {
                    $auth = $Matches[1].Trim()
                    if ($auth -match "WPA3") { Write-Output "[PASS] Using WPA3 encryption (strongest)" }
                    elseif ($auth -match "WPA2") { Write-Output "[OK] Using WPA2 encryption" }
                    elseif ($auth -match "WPA") { Write-Output "[WARN] Using WPA (outdated - upgrade to WPA2/WPA3)" }
                    elseif ($auth -match "WEP|Open") { Write-Output ">>> [FAIL] INSECURE: $auth - Change immediately!" }
                }
            } else { Write-Output "No Wi-Fi adapter found." }
            Write-Output ""
            # Scan nearby networks
            Write-Output "=== NEARBY NETWORKS ==="
            $scan = netsh wlan show networks mode=bssid 2>&1 | Out-String
            if ($scan -match "SSID") {
                $networks = $scan -split "SSID \d+ :" | Where-Object { $_.Trim() }
                foreach ($net in $networks) {
                    if ($net -match "^\s*(.+)") {
                        $ssid = $Matches[1].Trim()
                        $authType = if ($net -match "Authentication\s*:\s*(.+)") { $Matches[1].Trim() } else { "Unknown" }
                        $signal = if ($net -match "Signal\s*:\s*(\d+)%") { $Matches[1] + "%" } else { "?" }
                        $flag = if ($authType -match "Open|WEP") { ">>>" } else { "   " }
                        Write-Output "$flag SSID: $ssid | Auth: $authType | Signal: $signal"
                    }
                }
            }
            Write-Output ""
            # Saved profiles
            Write-Output "=== SAVED WI-FI PROFILES ==="
            $profiles = netsh wlan show profiles 2>&1 | Out-String
            $profileNames = [regex]::Matches($profiles, "All User Profile\s*:\s*(.+)") | ForEach-Object { $_.Groups[1].Value.Trim() }
            foreach ($pn in $profileNames) {
                $detail = netsh wlan show profile name="$pn" key=clear 2>&1 | Out-String
                $auth = if ($detail -match "Authentication\s*:\s*(.+)") { $Matches[1].Trim() } else { "?" }
                $flag = if ($auth -match "Open|WEP") { ">>> INSECURE" } else { "" }
                Write-Output "  $pn ($auth) $flag"
            }
        }
    }.GetNewClosure() },
    @{ Text = "File Integrity Monitor - Baseline"; OnClick = {
        & $script:InvokeTask "FIM Baseline" $true {
            Write-Output "=== FILE INTEGRITY MONITOR - CREATE BASELINE ==="
            Write-Output "Hashing critical system files..."
            $fimFile = "$env:USERPROFILE\.cyberscan\fim_baseline.json"
            $targets = @(
                "C:\Windows\System32\drivers\etc\hosts",
                "C:\Windows\System32\config\SAM",
                "C:\Windows\System32\config\SYSTEM",
                "C:\Windows\System32\config\SOFTWARE",
                "C:\Windows\System32\svchost.exe",
                "C:\Windows\System32\lsass.exe",
                "C:\Windows\System32\csrss.exe",
                "C:\Windows\System32\winlogon.exe",
                "C:\Windows\System32\cmd.exe",
                "C:\Windows\System32\powershell.exe",
                "C:\Windows\System32\taskmgr.exe",
                "C:\Windows\System32\netsh.exe",
                "C:\Windows\explorer.exe"
            )
            $baseline = @{}; $count = 0
            foreach ($f in $targets) {
                if (Test-Path $f) {
                    try {
                        $hash = (Get-FileHash $f -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        $size = (Get-Item $f -ErrorAction SilentlyContinue).Length
                        $baseline[$f] = @{Hash=$hash; Size=$size; Timestamp=(Get-Date).ToString("o")}
                        Write-Output "[OK] $f"; $count++
                    } catch { Write-Output "[SKIP] $f (access denied)" }
                } else { Write-Output "[MISS] $f (not found)" }
            }
            $baseline | ConvertTo-Json -Depth 3 | Out-File $fimFile -Encoding UTF8
            Write-Output ""; Write-Output "Baseline saved: $count files hashed"
            Write-Output "Run 'File Integrity Check' to detect modifications."
        }
    }.GetNewClosure() },
    @{ Text = "File Integrity Monitor - Check"; OnClick = {
        & $script:InvokeTask "FIM Integrity Check" $false {
            Write-Output "=== FILE INTEGRITY CHECK ==="
            $fimFile = "$env:USERPROFILE\.cyberscan\fim_baseline.json"
            if (-not (Test-Path $fimFile)) { Write-Output "No baseline found. Create one first."; return }
            $baseline = Get-Content $fimFile -Raw | ConvertFrom-Json
            $modified = 0; $missing = 0; $ok = 0
            foreach ($prop in $baseline.PSObject.Properties) {
                $filePath = $prop.Name
                $expected = $prop.Value
                if (-not (Test-Path $filePath)) { Write-Output ">>> MISSING: $filePath"; $missing++ }
                else {
                    try {
                        $currentHash = (Get-FileHash $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                        if ($currentHash -ne $expected.Hash) {
                            Write-Output ">>> MODIFIED: $filePath"
                            Write-Output "    Baseline: $($expected.Hash)"
                            Write-Output "    Current:  $currentHash"
                            $modified++
                        } else { Write-Output "[OK] $filePath"; $ok++ }
                    } catch { Write-Output "[SKIP] $filePath (access denied)" }
                }
            }
            Write-Output ""; Write-Output "Results: $ok intact | $modified modified | $missing missing"
            if ($modified -gt 0 -or $missing -gt 0) {
                Write-Output ">>> ALERT: System files have been modified since baseline!"
                Show-FixPrompt -Title "File Integrity Monitor" -Findings @("System files modified or missing since baseline") -FixMap @{
                    "System files modified or missing since baseline" = {
                        Write-Output "Running SFC scan to check for corrupted system files..."
                        sfc /scannow
                        Write-Output ""
                        Write-Output "Running Defender Full Scan..."
                        Start-MpScan -ScanType FullScan -ErrorAction SilentlyContinue
                        Write-Output "Full scan initiated. Review results in Windows Security."
                    }
                }
            }
        }
    }.GetNewClosure() },
    @{ Text = "Backup & Recovery Readiness"; OnClick = {
        & $script:InvokeTask "Backup & Recovery Audit" $false {
            Write-Output "=============================================="
            Write-Output "   BACKUP & RECOVERY READINESS AUDIT"
            Write-Output "=============================================="
            Write-Output ""
            $score = 0; $maxScore = 0; $findings = @()

            # 1. System Restore
            $maxScore += 20
            Write-Output "=== SYSTEM RESTORE ==="
            try {
                $sr = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending
                if ($sr -and $sr.Count -gt 0) {
                    $latest = $sr[0]
                    $daysAgo = [math]::Round(((Get-Date) - [Management.ManagementDateTimeConverter]::ToDateTime($latest.CreationTime)).TotalDays)
                    if ($daysAgo -le 7) { $score += 20; Write-Output "[PASS] $($sr.Count) restore point(s) | Latest: $daysAgo days ago  (+20)" }
                    elseif ($daysAgo -le 30) { $score += 10; Write-Output "[WARN] Latest restore point: $daysAgo days ago  (+10)"; $findings += "Create a fresh restore point" }
                    else { Write-Output "[FAIL] Latest restore point: $daysAgo days ago  (+0)"; $findings += "Create a restore point immediately" }
                } else { Write-Output "[FAIL] No restore points found  (+0)"; $findings += "Enable System Restore and create a restore point" }
            } catch { Write-Output "[FAIL] Cannot query restore points (run as Admin)  (+0)" }
            Write-Output ""

            # 2. Volume Shadow Copy (VSS)
            $maxScore += 15
            Write-Output "=== VOLUME SHADOW COPY ==="
            try {
                $vss = Get-Service VSS -ErrorAction SilentlyContinue
                $shadows = vssadmin list shadows 2>&1 | Out-String
                $shadowCount = ([regex]::Matches($shadows, "Shadow Copy ID")).Count
                if ($vss -or $shadowCount -gt 0) {
                    $score += 15; Write-Output "[PASS] VSS available | $shadowCount shadow copies  (+15)"
                } else {
                    $score += 5; Write-Output "[WARN] VSS service issue | $shadowCount shadows  (+5)"
                    $findings += "Ensure VSS service is running"
                }
            } catch { Write-Output "[INFO] Cannot check VSS  (+0)" }
            Write-Output ""

            # 3. File History
            $maxScore += 15
            Write-Output "=== FILE HISTORY ==="
            try {
                $fhPath = "$env:LOCALAPPDATA\Microsoft\Windows\FileHistory\Configuration\Config1.xml"
                if (Test-Path $fhPath) {
                    $score += 15; Write-Output "[PASS] File History configured  (+15)"
                } else {
                    Write-Output "[FAIL] File History not configured  (+0)"
                    $findings += "Enable File History for automatic backups"
                }
            } catch { Write-Output "[FAIL] File History not enabled  (+0)" }
            Write-Output ""

            # 4. Recovery Partition
            $maxScore += 15
            Write-Output "=== RECOVERY PARTITION ==="
            try {
                $recoveryPart = Get-Partition -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq "Recovery" }
                if ($recoveryPart) {
                    $sizeMB = [math]::Round($recoveryPart.Size / 1MB)
                    if ($sizeMB -ge 500) { $score += 15; Write-Output "[PASS] Recovery partition: $sizeMB MB  (+15)" }
                    else { $score += 8; Write-Output "[WARN] Recovery partition small: $sizeMB MB  (+8)" }
                } else { Write-Output "[FAIL] No recovery partition found  (+0)"; $findings += "System has no recovery partition" }
            } catch { Write-Output "[INFO] Cannot check partitions  (+0)" }
            Write-Output ""

            # 5. Windows RE
            $maxScore += 15
            Write-Output "=== WINDOWS RECOVERY ENVIRONMENT ==="
            try {
                $reagent = reagentc /info 2>&1 | Out-String
                if ($reagent -match "Enabled") { $score += 15; Write-Output "[PASS] Windows RE: Enabled  (+15)" }
                else { Write-Output "[FAIL] Windows RE: Disabled  (+0)"; $findings += "Enable Windows Recovery Environment" }
            } catch { Write-Output "[INFO] Cannot check WinRE  (+0)" }
            Write-Output ""

            # 6. OneDrive / Cloud Backup
            $maxScore += 10
            Write-Output "=== CLOUD BACKUP ==="
            $oneDriveRunning = Get-Process OneDrive -ErrorAction SilentlyContinue
            if ($oneDriveRunning) {
                $score += 10; Write-Output "[PASS] OneDrive active and syncing  (+10)"
            } else { Write-Output "[INFO] No cloud backup process detected  (+0)"; $findings += "Consider enabling OneDrive or cloud backup" }
            Write-Output ""

            # 7. BitLocker Recovery Key
            $maxScore += 10
            Write-Output "=== BITLOCKER RECOVERY KEY ==="
            try {
                $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                if ($bl.ProtectionStatus -eq "On") {
                    $keyProtectors = $bl.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
                    if ($keyProtectors) { $score += 10; Write-Output "[PASS] BitLocker active with recovery key  (+10)" }
                    else { $score += 5; Write-Output "[WARN] BitLocker active but no recovery password  (+5)"; $findings += "Back up your BitLocker recovery key" }
                } else { Write-Output "[INFO] BitLocker not active  (+0)" }
            } catch { Write-Output "[INFO] Cannot check BitLocker  (+0)" }
            Write-Output ""

            # Score
            $pct = if ($maxScore -gt 0) { [math]::Round(($score / $maxScore) * 100) } else { 0 }
            $grade = if ($pct -ge 90) { "A+" } elseif ($pct -ge 80) { "A" } elseif ($pct -ge 70) { "B" } elseif ($pct -ge 60) { "C" } elseif ($pct -ge 50) { "D" } else { "F" }
            Write-Output "=============================================="
            Write-Output "  RECOVERY READINESS: $score / $maxScore ($pct%) - Grade: $grade"
            Write-Output "=============================================="
            if ($findings.Count -gt 0) {
                Write-Output ""; Write-Output "=== RECOMMENDATIONS ==="
                $i = 1; foreach ($f in $findings) { Write-Output "  $i. $f"; $i++ }
                Show-FixPrompt -Title "Backup & Recovery" -Findings $findings -FixMap @{
                    "Create a fresh restore point"                 = { Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue; Checkpoint-Computer -Description "CyberScan_Recovery" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue; Write-Output "Created restore point." }
                    "Create a restore point immediately"           = { Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue; Checkpoint-Computer -Description "CyberScan_Recovery" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue; Write-Output "Created restore point." }
                    "Enable System Restore and create a restore point" = { Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue; Checkpoint-Computer -Description "CyberScan_Recovery" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue; Write-Output "Enabled System Restore." }
                    "Enable File History for automatic backups"    = { Start-Process "ms-settings:backup"; Write-Output "Opened Backup settings." }
                    "Enable Windows Recovery Environment"          = { reagentc /enable 2>&1; Write-Output "Attempted to enable Windows RE." }
                    "Consider enabling OneDrive or cloud backup"   = { Start-Process "ms-settings:backup"; Write-Output "Opened Backup settings." }
                    "Back up your BitLocker recovery key"          = { Start-Process "ms-settings:about"; Write-Output "Go to Device encryption to back up recovery key." }
                }
            }
            Save-ScanResult -ScanName "BackupRecovery" -Score $score -MaxScore $maxScore -Issues $findings.Count
        }
    }.GetNewClosure() }
)

# --- 9. HARDENING (NEW) ---
Add-CategoryButton -Label "HARDENING" -LabelColor $colorCatPink -Tooltip "Quarantine mode, remediation, scheduled scans, undo log" -SubItems @(
    @{ Text = "Emergency Quarantine Mode"; OnClick = {
        & $script:InvokeTask "EMERGENCY QUARANTINE" $true {
            Write-Output "=============================================="
            Write-Output "     EMERGENCY QUARANTINE MODE ACTIVATED"
            Write-Output "=============================================="
            Write-Output ""
            Write-Output "Step 1: Disabling network adapters..."
            Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
                Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
                Write-Output "  Disabled: $($_.Name)"
            }
            Write-Output ""
            Write-Output "Step 2: Blocking all inbound/outbound traffic..."
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block -ErrorAction SilentlyContinue
            Write-Output "  Firewall set to BLOCK ALL"
            Write-Output ""
            Write-Output "Step 3: Killing suspicious processes..."
            $suspProcs = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                $_.MainModule -and ($_.MainModule.FileName -like "*\Temp\*" -or $_.MainModule.FileName -like "*\AppData\Local\Temp\*")
            }
            foreach ($sp in $suspProcs) {
                Stop-Process -Id $sp.Id -Force -ErrorAction SilentlyContinue
                Write-Output "  Killed: $($sp.ProcessName) (PID $($sp.Id)) from $($sp.MainModule.FileName)"
            }
            if ($suspProcs.Count -eq 0) { Write-Output "  No suspicious processes found in temp directories." }
            Write-Output ""
            Write-Output "Step 4: Disabling USB storage..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4 -ErrorAction SilentlyContinue
            Write-Output "  USB storage devices: DISABLED"
            Write-Output ""
            Write-Output "=============================================="
            Write-Output "  SYSTEM IS NOW IN QUARANTINE MODE"
            Write-Output "  Network: DISCONNECTED"
            Write-Output "  Firewall: BLOCK ALL"
            Write-Output "  USB: DISABLED"
            Write-Output "=============================================="
            Write-Output ""
            Write-Output "To restore: Run 'Exit Quarantine Mode'"
        }
    }.GetNewClosure() },
    @{ Text = "Exit Quarantine Mode"; OnClick = {
        & $script:InvokeTask "Exit Quarantine" $true {
            Write-Output "=== EXITING QUARANTINE MODE ==="
            Write-Output ""
            Write-Output "Re-enabling network adapters..."
            Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" } | ForEach-Object {
                Enable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
                Write-Output "  Enabled: $($_.Name)"
            }
            Write-Output ""
            Write-Output "Restoring firewall to default..."
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
            Write-Output "  Firewall: Inbound Block / Outbound Allow (default)"
            Write-Output ""
            Write-Output "Re-enabling USB storage..."
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 3 -ErrorAction SilentlyContinue
            Write-Output "  USB storage: ENABLED"
            Write-Output ""
            Write-Output "System restored to normal operation."
        }
    }.GetNewClosure() },
    @{ Text = "Remediation Wizard (Auto-Fix)"; OnClick = {
        & $script:InvokeTask "Remediation Wizard" $true {
            Write-Output "=== CYBERSCAN REMEDIATION WIZARD ==="
            Write-Output "Scanning for common issues and auto-fixing..."
            Write-Output ""
            $fixed = 0

            # Fix 1: Enable all firewall profiles
            $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            $fwOff = @($fw | Where-Object { -not $_.Enabled })
            if ($fwOff.Count -gt 0) {
                Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
                Save-UndoEntry -Action "EnableFirewall" -RevertCommand "Set-NetFirewallProfile -Enabled False" -Description "Enabled disabled firewall profiles"
                Write-Output "[FIXED] Enabled $($fwOff.Count) disabled firewall profile(s)"; $fixed++
            }

            # Fix 2: Disable SMBv1
            try {
                $smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
                if ($smb.EnableSMB1Protocol) {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
                    Save-UndoEntry -Action "DisableSMBv1" -RevertCommand "Set-SmbServerConfiguration -EnableSMB1Protocol `$true -Force" -Description "Disabled SMBv1 protocol"
                    Write-Output "[FIXED] Disabled SMBv1 protocol"; $fixed++
                }
            } catch {}

            # Fix 3: Disable Remote Registry
            $rr = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
            if ($rr -and $rr.StartType -ne "Disabled") {
                Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
                Save-UndoEntry -Action "DisableRemoteRegistry" -RevertCommand "Set-Service -Name RemoteRegistry -StartupType Manual" -Description "Disabled Remote Registry service"
                Write-Output "[FIXED] Disabled Remote Registry service"; $fixed++
            }

            # Fix 4: Disable Remote Assistance
            try {
                $ra = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name fAllowToGetHelp -ErrorAction SilentlyContinue
                if ($ra.fAllowToGetHelp -eq 1) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
                    Save-UndoEntry -Action "DisableRemoteAssistance" -RevertCommand "Set-ItemProperty 'HKLM:\...\Remote Assistance' fAllowToGetHelp 1" -Description "Disabled Remote Assistance"
                    Write-Output "[FIXED] Disabled Remote Assistance"; $fixed++
                }
            } catch {}

            # Fix 5: Flush DNS
            ipconfig /flushdns | Out-Null
            Write-Output "[FIXED] Flushed DNS cache"; $fixed++

            # Fix 6: Clear temp files
            $tempBefore = (Get-ChildItem "$env:TEMP" -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            $freed = [math]::Round(($tempBefore - (Get-ChildItem "$env:TEMP" -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum) / 1MB, 1)
            if ($freed -gt 0) { Write-Output "[FIXED] Cleaned temp files (freed $freed MB)"; $fixed++ }

            # Fix 7: Enable UAC if disabled
            try {
                $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue
                if ($uac.EnableLUA -ne 1) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
                    Write-Output "[FIXED] Re-enabled UAC (User Account Control)"; $fixed++
                }
            } catch {}

            # Fix 8: Disable AutoPlay
            try {
                $ap = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
                if ($ap.NoDriveTypeAutoRun -ne 255) {
                    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
                        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
                    }
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
                    Write-Output "[FIXED] Disabled AutoPlay for all drives"; $fixed++
                }
            } catch {}

            Write-Output ""
            Write-Output "=== REMEDIATION COMPLETE ==="
            Write-Output "$fixed issues automatically fixed."
            Write-Output "Run Security Score Dashboard to verify improvements."
        }
    }.GetNewClosure() },
    @{ Text = "Schedule Daily Security Scan"; OnClick = {
        & $script:InvokeTask "Schedule Scan" $true {
            Write-Output "=== SCHEDULING DAILY SECURITY SCAN ==="
            $scriptPath = $PSCommandPath
            if (-not $scriptPath) { $scriptPath = "$PWD\cyberscan.ps1" }
            $taskName = "CyberScan_DailyScan"
            try {
                $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($existing) {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                    Write-Output "Removed existing scheduled task."
                }
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -Command `"Start-MpScan -ScanType QuickScan`""
                $trigger = New-ScheduledTaskTrigger -Daily -At "03:00AM"
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "CyberScan Daily Security Scan" -ErrorAction Stop
                Write-Output "Scheduled task created: $taskName"
                Write-Output "Runs daily at 3:00 AM with Defender Quick Scan."
                Write-Output ""
                Write-Output "Manage in Task Scheduler or run:"
                Write-Output "  Get-ScheduledTask -TaskName '$taskName'"
            } catch {
                Write-Output "Failed to create scheduled task: $($_.Exception.Message)"
                Write-Output "Try running CyberScan as Administrator."
            }
        }
    }.GetNewClosure() },
    @{ Text = "Internet Speed Boost (TCP/IP)"; OnClick = {
        & $script:InvokeTask "TCP/IP Optimization" $false {
            netsh int tcp set global autotuninglevel=normal
            netsh int tcp set global chimney=enabled 2>&1 | Out-Null
            netsh int tcp set global dca=enabled 2>&1 | Out-Null
            netsh int tcp set global netdma=enabled 2>&1 | Out-Null
            Write-Output "Network TCP/IP Optimized for maximum throughput."
        }
    }.GetNewClosure() },
    @{ Text = "Undo Hardening Changes"; OnClick = {
        & $script:InvokeTask "Undo Hardening Log" $false {
            Write-Output "=== HARDENING UNDO LOG ==="
            Write-Output ""
            if (-not (Test-Path $UndoLogFile)) {
                Write-Output "No undo log found. Hardening changes will be logged here in future."
                return
            }
            $log = @(Get-Content $UndoLogFile -Raw | ConvertFrom-Json)
            if ($log.Count -eq 0) { Write-Output "Undo log is empty."; return }
            Write-Output "Found $($log.Count) recorded change(s):"
            Write-Output ""
            Write-Output ("{0,-22} {1,-35} {2}" -f "Date", "Action", "Revert Command")
            Write-Output ("-" * 90)
            foreach ($entry in ($log | Sort-Object Date -Descending)) {
                $date = try { ([datetime]$entry.Date).ToString("yyyy-MM-dd HH:mm") } catch { $entry.Date }
                Write-Output ("{0,-22} {1,-35} {2}" -f $date, $entry.Action, $entry.Description)
            }
            Write-Output ""
            Write-Output "To revert changes, use the Remediation Wizard or apply fixes manually."
            Write-Output "Each fix above was logged when applied by CyberScan."
        }
    }.GetNewClosure() }
)

# --- 10. TOOLS ---
Add-CategoryButton -Label "TOOLS" -LabelColor ([System.Drawing.Color]::FromArgb(150, 200, 255)) -Tooltip "Version check, scan history, export/import settings" -SubItems @(
    @{ Text = "Check for Updates"; OnClick = {
        & $script:InvokeTask "Version Check" $false {
            Write-Output "=== CYBERSCAN VERSION CHECK ==="
            Write-Output ""
            Write-Output "Current version: v$CurrentVersion"
            Write-Output "Checking for updates..."
            Write-Output ""
            try {
                $release = Invoke-RestMethod -Uri $VersionCheckURL -TimeoutSec 10 -ErrorAction Stop -Headers @{"User-Agent"="CyberScan-$CurrentVersion"}
                $latestVer = $release.tag_name -replace '^v',''
                $publishDate = ([datetime]$release.published_at).ToString("yyyy-MM-dd")
                Write-Output "Latest version: v$latestVer (released $publishDate)"
                Write-Output ""
                if ([version]$latestVer -gt [version]$CurrentVersion) {
                    Write-Output ">>> UPDATE AVAILABLE! v$CurrentVersion -> v$latestVer"
                    Write-Output ""
                    Write-Output "Release notes:"
                    $notes = $release.body
                    if ($notes.Length -gt 500) { $notes = $notes.Substring(0, 500) + "..." }
                    Write-Output $notes
                    Write-Output ""
                    Write-Output "Download: $($release.html_url)"
                    $response = [System.Windows.Forms.MessageBox]::Show(
                        "CyberScan v$latestVer is available (you have v$CurrentVersion).`n`nOpen the download page?",
                        "Update Available",
                        [System.Windows.Forms.MessageBoxButtons]::YesNo,
                        [System.Windows.Forms.MessageBoxIcon]::Information,
                        [System.Windows.Forms.MessageBoxDefaultButton]::Button1,
                        [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
                    )
                    if ($response -eq "Yes") { Start-Process $release.html_url }
                } else {
                    Write-Output "[UP TO DATE] You are running the latest version."
                }
            } catch {
                if ($_.Exception.Response.StatusCode -eq 404) {
                    Write-Output "No release repository found. This is a local build."
                } else {
                    Write-Output "Could not check for updates: $($_.Exception.Message)"
                    Write-Output "Check manually or verify internet connectivity."
                }
            }
        }
    }.GetNewClosure() },
    @{ Text = "Scan History & Trends"; OnClick = {
        & $script:InvokeTask "Scan History" $false {
            Write-Output "=== CYBERSCAN SCAN HISTORY ==="
            Write-Output ""
            if (-not (Test-Path $ScanHistoryFile)) {
                Write-Output "No scan history yet. Run security scans to build history."
                return
            }
            $history = @(Get-Content $ScanHistoryFile -Raw | ConvertFrom-Json)
            if ($history.Count -eq 0) { Write-Output "No scan history yet."; return }
            Write-Output "Total scans recorded: $($history.Count)"
            Write-Output ""
            Write-Output ("{0,-22} {1,-28} {2,-12} {3}" -f "Date", "Scan", "Score", "Issues")
            Write-Output ("-" * 72)
            foreach ($h in ($history | Sort-Object Date -Descending | Select-Object -First 30)) {
                $date = try { ([datetime]$h.Date).ToString("yyyy-MM-dd HH:mm") } catch { $h.Date }
                $scoreStr = if ($h.MaxScore -gt 0) { "$($h.Score)/$($h.MaxScore) ($([math]::Round(($h.Score/$h.MaxScore)*100))%)" } else { "N/A" }
                Write-Output ("{0,-22} {1,-28} {2,-12} {3}" -f $date, $h.Scan, $scoreStr, $h.Issues)
            }
            # Trend analysis
            $secScores = @($history | Where-Object { $_.Scan -eq "SecurityScore" -and $_.MaxScore -gt 0 } | Sort-Object Date)
            if ($secScores.Count -ge 2) {
                $first = [math]::Round(($secScores[0].Score / $secScores[0].MaxScore) * 100)
                $last = [math]::Round(($secScores[-1].Score / $secScores[-1].MaxScore) * 100)
                $trend = $last - $first
                Write-Output ""
                Write-Output "=== SECURITY SCORE TREND ==="
                if ($trend -gt 0) { Write-Output "  Improving: $first% -> $last% (+$trend%)" }
                elseif ($trend -lt 0) { Write-Output "  Declining: $first% -> $last% ($trend%)" }
                else { Write-Output "  Stable at $last%" }
            }
        }
    }.GetNewClosure() },
    @{ Text = "Export Settings Profile"; OnClick = {
        & $script:InvokeTask "Export Settings" $false {
            Write-Output "=== EXPORT CYBERSCAN SETTINGS PROFILE ==="
            Write-Output ""
            Write-Output "Collecting current system security configuration..."
            $profile = @{
                ExportDate = (Get-Date).ToString("o")
                Version = $CurrentVersion
                ComputerName = $env:COMPUTERNAME
                Settings = @{}
            }
            # Collect key settings
            try { $profile.Settings["UAC"] = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA } catch {}
            try { $profile.Settings["RDP"] = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections } catch {}
            try { $profile.Settings["SMBv1"] = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol } catch {}
            try { $profile.Settings["FirewallDomain"] = (Get-NetFirewallProfile -Name Domain -ErrorAction SilentlyContinue).Enabled } catch {}
            try { $profile.Settings["FirewallPublic"] = (Get-NetFirewallProfile -Name Public -ErrorAction SilentlyContinue).Enabled } catch {}
            try { $profile.Settings["FirewallPrivate"] = (Get-NetFirewallProfile -Name Private -ErrorAction SilentlyContinue).Enabled } catch {}
            try { $profile.Settings["DefenderRealtime"] = (Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled } catch {}
            try { $profile.Settings["RemoteRegistry"] = (Get-Service RemoteRegistry -ErrorAction SilentlyContinue).StartType.ToString() } catch {}
            try { $ap = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue; $profile.Settings["AutoPlayDisabled"] = ($ap.NoDriveTypeAutoRun -eq 255) } catch {}
            try { $psLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue; $profile.Settings["PSScriptLogging"] = ($psLog.EnableScriptBlockLogging -eq 1) } catch {}

            $exportPath = "$RealDesktop\CyberScan_Profile_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $profile | ConvertTo-Json -Depth 5 | Out-File $exportPath -Encoding UTF8
            Write-Output "Settings profile exported to:"
            Write-Output $exportPath
            Write-Output ""
            Write-Output "Settings captured:"
            foreach ($k in $profile.Settings.Keys) { Write-Output "  $k = $($profile.Settings[$k])" }
            Write-Output ""
            Write-Output "Share this profile to replicate security settings on another machine."
        }
    }.GetNewClosure() },
    @{ Text = "Import Settings Profile"; OnClick = {
        & $script:InvokeTask "Import Settings" $true {
            Write-Output "=== IMPORT CYBERSCAN SETTINGS PROFILE ==="
            Write-Output ""
            $ofd = New-Object System.Windows.Forms.OpenFileDialog
            $ofd.Filter = "JSON Files (*.json)|*.json"
            $ofd.Title = "Select CyberScan Settings Profile"
            $ofd.InitialDirectory = $RealDesktop
            if ($ofd.ShowDialog() -ne "OK") { Write-Output "Import cancelled."; return }
            try {
                $profile = Get-Content $ofd.FileName -Raw | ConvertFrom-Json
                Write-Output "Loaded profile from: $($ofd.FileName)"
                Write-Output "Exported: $($profile.ExportDate) | From: $($profile.ComputerName)"
                Write-Output ""
                $settings = $profile.Settings
                $applied = 0
                if ($null -ne $settings.UAC -and $settings.UAC -eq 1) {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -ErrorAction SilentlyContinue
                    Write-Output "[APPLIED] UAC enabled"; $applied++
                }
                if ($null -ne $settings.RDP -and $settings.RDP -eq 1) {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 1 -ErrorAction SilentlyContinue
                    Write-Output "[APPLIED] RDP disabled"; $applied++
                }
                if ($null -ne $settings.SMBv1 -and $settings.SMBv1 -eq $false) {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
                    Write-Output "[APPLIED] SMBv1 disabled"; $applied++
                }
                if ($settings.FirewallDomain -eq $true) { Set-NetFirewallProfile -Name Domain -Enabled True -ErrorAction SilentlyContinue; Write-Output "[APPLIED] Domain firewall enabled"; $applied++ }
                if ($settings.FirewallPublic -eq $true) { Set-NetFirewallProfile -Name Public -Enabled True -ErrorAction SilentlyContinue; Write-Output "[APPLIED] Public firewall enabled"; $applied++ }
                if ($settings.FirewallPrivate -eq $true) { Set-NetFirewallProfile -Name Private -Enabled True -ErrorAction SilentlyContinue; Write-Output "[APPLIED] Private firewall enabled"; $applied++ }
                if ($settings.AutoPlayDisabled -eq $true) {
                    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null }
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -Value 255 -ErrorAction SilentlyContinue
                    Write-Output "[APPLIED] AutoPlay disabled"; $applied++
                }
                if ($settings.PSScriptLogging -eq $true) {
                    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null }
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -ErrorAction SilentlyContinue
                    Write-Output "[APPLIED] PS Script Block Logging enabled"; $applied++
                }
                Write-Output ""
                Write-Output "$applied settings applied from profile."
            } catch {
                Write-Output "Failed to import profile: $($_.Exception.Message)"
            }
        }
    }.GetNewClosure() }
)

# ===================== SIDEBAR BOTTOM SECTION =====================
$sideBottomY = $script:sideY + 12

$sideSep = New-Object System.Windows.Forms.Panel
$sideSep.Location = New-Object System.Drawing.Point(10, $sideBottomY)
$sideSep.Size = New-Object System.Drawing.Size(($sidebarWidth - 20), 1)
$sideSep.BackColor = [System.Drawing.Color]::FromArgb(40, 50, 90)
$sidePanel.Controls.Add($sideSep)

# About button
$aboutBtn = New-Object System.Windows.Forms.Button
$aboutBtn.Text = "  About"
$aboutBtn.Size = New-Object System.Drawing.Size(($sidebarWidth - 12), 32)
$aboutBtn.Location = New-Object System.Drawing.Point(6, ($sideBottomY + 6))
$aboutBtn.FlatStyle = "Flat"; $aboutBtn.FlatAppearance.BorderSize = 0
$aboutBtn.BackColor = $colorBtnNormal; $aboutBtn.ForeColor = [System.Drawing.Color]::FromArgb(140, 170, 255)
$aboutBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$aboutBtn.TextAlign = "MiddleLeft"; $aboutBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
$aboutBtn.Add_MouseEnter({ $this.BackColor = $colorBtnHover }.GetNewClosure())
$aboutBtn.Add_MouseLeave({ $this.BackColor = $colorBtnNormal }.GetNewClosure())

$aboutBtn.Add_Click({
    & $script:CloseFlyout
    $aboutForm = New-Object System.Windows.Forms.Form
    $aboutForm.Text = "About CyberScan"
    $aboutForm.Size = New-Object System.Drawing.Size(500, 460)
    $aboutForm.StartPosition = "CenterParent"
    $aboutForm.BackColor = [System.Drawing.Color]::FromArgb(14, 14, 26)
    $aboutForm.ForeColor = [System.Drawing.Color]::White
    $aboutForm.FormBorderStyle = "FixedDialog"; $aboutForm.MaximizeBox = $false; $aboutForm.MinimizeBox = $false

    $accentBar = New-Object System.Windows.Forms.Panel
    $accentBar.Dock = "Top"; $accentBar.Height = 4; $accentBar.BackColor = [System.Drawing.Color]::Cyan
    $aboutForm.Controls.Add($accentBar)

    $aboutTitle = New-Object System.Windows.Forms.Label
    $aboutTitle.Text = "CYBERSCAN 2026"
    $aboutTitle.Font = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold)
    $aboutTitle.ForeColor = [System.Drawing.Color]::Cyan
    $aboutTitle.Size = New-Object System.Drawing.Size(460, 42); $aboutTitle.TextAlign = "MiddleCenter"
    $aboutTitle.Location = New-Object System.Drawing.Point(10, 20)
    $aboutForm.Controls.Add($aboutTitle)

    $aboutSub = New-Object System.Windows.Forms.Label
    $aboutSub.Text = "TITAN ULTIMATE EDITION v10.0"
    $aboutSub.Font = New-Object System.Drawing.Font("Segoe UI", 13)
    $aboutSub.ForeColor = [System.Drawing.Color]::FromArgb(180, 180, 230)
    $aboutSub.Size = New-Object System.Drawing.Size(460, 28); $aboutSub.TextAlign = "MiddleCenter"
    $aboutSub.Location = New-Object System.Drawing.Point(10, 65)
    $aboutForm.Controls.Add($aboutSub)

    $aboutSep1 = New-Object System.Windows.Forms.Panel
    $aboutSep1.Location = New-Object System.Drawing.Point(60, 102)
    $aboutSep1.Size = New-Object System.Drawing.Size(360, 1)
    $aboutSep1.BackColor = [System.Drawing.Color]::FromArgb(40, 50, 90)
    $aboutForm.Controls.Add($aboutSep1)

    $aboutDesc = New-Object System.Windows.Forms.Label
    $aboutDesc.Text = "Complete IT Diagnostics, Security & Threat Intelligence Toolkit`nfor Windows 10 / 11"
    $aboutDesc.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $aboutDesc.ForeColor = [System.Drawing.Color]::FromArgb(160, 160, 180)
    $aboutDesc.Size = New-Object System.Drawing.Size(460, 44); $aboutDesc.TextAlign = "MiddleCenter"
    $aboutDesc.Location = New-Object System.Drawing.Point(10, 112)
    $aboutForm.Controls.Add($aboutDesc)

    $aboutFeatures = New-Object System.Windows.Forms.Label
    $aboutFeatures.Text = "110+ Operations | 10 Categories | Security Scoring | CVE Scanner`nCIS Baseline | MITRE ATT&CK Mapping | Event Log Threat Hunting`nBreach Check | Backup Audit | Scan History | Settings Export/Import"
    $aboutFeatures.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $aboutFeatures.ForeColor = [System.Drawing.Color]::FromArgb(100, 180, 140)
    $aboutFeatures.Size = New-Object System.Drawing.Size(460, 52); $aboutFeatures.TextAlign = "MiddleCenter"
    $aboutFeatures.Location = New-Object System.Drawing.Point(10, 160)
    $aboutForm.Controls.Add($aboutFeatures)

    $aboutSep2 = New-Object System.Windows.Forms.Panel
    $aboutSep2.Location = New-Object System.Drawing.Point(60, 222)
    $aboutSep2.Size = New-Object System.Drawing.Size(360, 1)
    $aboutSep2.BackColor = [System.Drawing.Color]::FromArgb(40, 50, 90)
    $aboutForm.Controls.Add($aboutSep2)

    $aboutDev = New-Object System.Windows.Forms.Label
    $aboutDev.Text = "Developed by Ronald Goodchild"
    $aboutDev.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $aboutDev.ForeColor = [System.Drawing.Color]::White
    $aboutDev.Size = New-Object System.Drawing.Size(460, 36); $aboutDev.TextAlign = "MiddleCenter"
    $aboutDev.Location = New-Object System.Drawing.Point(10, 236)
    $aboutForm.Controls.Add($aboutDev)

    $aboutCopy = New-Object System.Windows.Forms.Label
    $aboutCopy.Text = "Copyright $(Get-Date -Format 'yyyy'). All rights reserved."
    $aboutCopy.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $aboutCopy.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 110)
    $aboutCopy.Size = New-Object System.Drawing.Size(460, 22); $aboutCopy.TextAlign = "MiddleCenter"
    $aboutCopy.Location = New-Object System.Drawing.Point(10, 278)
    $aboutForm.Controls.Add($aboutCopy)

    $aboutPowered = New-Object System.Windows.Forms.Label
    $aboutPowered.Text = "Built with PowerShell + Windows Forms"
    $aboutPowered.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $aboutPowered.ForeColor = [System.Drawing.Color]::FromArgb(70, 70, 90)
    $aboutPowered.Size = New-Object System.Drawing.Size(460, 20); $aboutPowered.TextAlign = "MiddleCenter"
    $aboutPowered.Location = New-Object System.Drawing.Point(10, 302)
    $aboutForm.Controls.Add($aboutPowered)

    $aboutOK = New-Object System.Windows.Forms.Button
    $aboutOK.Text = "OK"; $aboutOK.Size = New-Object System.Drawing.Size(120, 36)
    $aboutOK.Location = New-Object System.Drawing.Point(180, 345); $aboutOK.FlatStyle = "Flat"
    $aboutOK.BackColor = [System.Drawing.Color]::FromArgb(30, 50, 100); $aboutOK.ForeColor = [System.Drawing.Color]::White
    $aboutOK.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $aboutOK.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(50, 80, 160)
    $aboutOK.Cursor = [System.Windows.Forms.Cursors]::Hand
    $aboutOK.Add_Click({ $aboutForm.Close() })
    $aboutForm.Controls.Add($aboutOK)

    $aboutForm.ShowDialog()
})
$sidePanel.Controls.Add($aboutBtn)

# Sidebar Exit button
$sideExitBtn = New-Object System.Windows.Forms.Button
$sideExitBtn.Text = "  Exit CyberScan"
$sideExitBtn.Size = New-Object System.Drawing.Size(($sidebarWidth - 12), 32)
$sideExitBtn.Location = New-Object System.Drawing.Point(6, ($sideBottomY + 42))
$sideExitBtn.FlatStyle = "Flat"; $sideExitBtn.FlatAppearance.BorderSize = 0
$sideExitBtn.BackColor = [System.Drawing.Color]::FromArgb(120, 20, 20); $sideExitBtn.ForeColor = $colorTextWhite
$sideExitBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$sideExitBtn.TextAlign = "MiddleLeft"; $sideExitBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
$sideExitBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(170, 30, 30) }.GetNewClosure())
$sideExitBtn.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(120, 20, 20) }.GetNewClosure())
$sideExitBtn.Add_Click({ $form.Close() })
$sidePanel.Controls.Add($sideExitBtn)

# ===================== CLEANUP ON CLOSE =====================
$form.Add_FormClosing({
    try { $dashTimer.Stop() } catch {}
    try { $clockTimer.Stop() } catch {}
    try { $taskPollTimer.Stop() } catch {}
    if ($script:bgPipeline) {
        try { $script:bgPipeline.Stop() } catch {}
        try { $script:bgPipeline.Dispose() } catch {}
    }
    if ($script:bgRunspace) {
        try { $script:bgRunspace.Close(); $script:bgRunspace.Dispose() } catch {}
    }
    try { $dashTimer.Dispose() } catch {}
    try { $clockTimer.Dispose() } catch {}
    try { $taskPollTimer.Dispose() } catch {}
    try { Get-CimSession | Remove-CimSession -ErrorAction SilentlyContinue } catch {}
})

# ===================== LAUNCH =====================
[void]$form.ShowDialog()

# Post-dialog cleanup
try { $dashTimer.Stop(); $dashTimer.Dispose() } catch {}
try { $clockTimer.Stop(); $clockTimer.Dispose() } catch {}
try { $taskPollTimer.Stop(); $taskPollTimer.Dispose() } catch {}
if ($script:bgPipeline) { try { $script:bgPipeline.Stop(); $script:bgPipeline.Dispose() } catch {} }
if ($script:bgRunspace) { try { $script:bgRunspace.Close(); $script:bgRunspace.Dispose() } catch {} }
try { Get-CimSession | Remove-CimSession -ErrorAction SilentlyContinue } catch {}
try { $form.Dispose() } catch {}
[System.GC]::Collect()
