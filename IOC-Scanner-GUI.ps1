<#
.SYNOPSIS
    Windows IOC Scanner - WPF GUI with VirusTotal Integration
.DESCRIPTION
    One-click malware IOC scanner with a graphical interface.
    Checks 16 categories of malware indicators and optionally
    queries VirusTotal for file reputation.
.NOTES
    Run as Administrator for full functionality.
#>

param([switch]$SkipAdminCheck)

$script:VTKeyPath = Join-Path $env:APPDATA "IOC-Scanner\vt_key.dat"
$script:VTKeySalt = Join-Path $env:APPDATA "IOC-Scanner\vt_salt.dat"

function Save-VTKey {
    param([string]$ApiKey)
    $dir = Split-Path $script:VTKeyPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    [System.IO.File]::WriteAllBytes($script:VTKeySalt, $salt)
    $encKey = [System.Text.Encoding]::UTF8.GetBytes($ApiKey)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($encKey, $salt, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($script:VTKeyPath, $encrypted)
}

function Load-VTKey {
    if (-not (Test-Path $script:VTKeyPath)) { return $null }
    try {
        $encrypted = [System.IO.File]::ReadAllBytes($script:VTKeyPath)
        $salt = [System.IO.File]::ReadAllBytes($script:VTKeySalt)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $salt, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    } catch { return $null }
}

function Remove-VTKey {
    if (Test-Path $script:VTKeyPath) { Remove-Item $script:VTKeyPath -Force }
    if (Test-Path $script:VTKeySalt) { Remove-Item $script:VTKeySalt -Force }
}

function Test-VTApiKey {
    param([string]$Key)
    try {
        $null = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/users/me" -Headers @{ "x-apikey" = $Key } -Method GET -TimeoutSec 10
        return $true
    } catch { return $false }
}

# Load XAML
$xamlPath = Join-Path (Split-Path $MyInvocation.MyCommand.Path) "xaml.txt"
$xaml = [System.IO.File]::ReadAllText($xamlPath)

[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationCore')
[void][System.Reflection.Assembly]::LoadWithPartialName('WindowsBase')

$xml = [System.Xml.XmlDocument]::new()
$xml.LoadXml($xaml)
$reader = [System.Xml.XmlNodeReader]::new($xml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$btnScan=$window.FindName("btnScan"); $btnExport=$window.FindName("btnExport"); $btnClear=$window.FindName("btnClear")
$btnSettings=$window.FindName("btnSettings"); $chkDeepScan=$window.FindName("chkDeepScan"); $chkVT=$window.FindName("chkVT")
$dgResults=$window.FindName("dgResults"); $txtProgress=$window.FindName("txtProgress"); $txtTimer=$window.FindName("txtTimer")
$txtCritical=$window.FindName("txtCritical"); $txtHigh=$window.FindName("txtHigh"); $txtMedium=$window.FindName("txtMedium")
$txtLow=$window.FindName("txtLow"); $txtTotal=$window.FindName("txtTotal"); $txtStatus=$window.FindName("txtStatus")
$txtVTStatus=$window.FindName("txtVTStatus"); $progressBar=$window.FindName("progressBar"); $adminStatus=$window.FindName("AdminStatus")

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$adminStatus.Text = if ($isAdmin) { "Running as Administrator" } else { "Standard User (some checks limited)" }
$adminStatus.Foreground = if ($isAdmin) { "#44cc44" } else { "#ccaa00" }

$savedVTKey = Load-VTKey
if ($savedVTKey) { $chkVT.IsEnabled=$true; $txtVTStatus.Text="VT API: Configured"; $txtVTStatus.Foreground="#44cc44" }
else { $chkVT.IsEnabled=$false; $txtVTStatus.Text="VT API: Not configured"; $txtVTStatus.Foreground="#cc4444" }

$script:findings = [System.Collections.ArrayList]::new()
$script:scanComplete = $true
$script:scanError = $null

$safeProcesses = @("Idle","System","Registry","Memory Compression","dismhost","csrss","smss","lsass","wininit","winlogon","services","svchost","dllhost","conhost","taskhostw","RuntimeBroker","SearchIndexer","SecurityHealthService","WmiPrvSE","WUDFHost","audiodg","dwm","fontdrvhost","msiexec","WerFault","bgtaskhost","TextInputHost","ApplicationFrameHost","ShellExperienceHost","StartMenuExperienceHost","systemsettings","ctfmon","taskmgr","cmd","powershell","pwsh","WindowsTerminal","explorer","OneDrive","Discord","Spotify","Brave","chrome","firefox","msedge","opera","Steam","Code","steamwebhelper","mstsc")
$safePorts = @(80,443,8080,8443,53,993,995,587,27015,27016,27017,27018,27019,27020,51820,3389,11434,27036,27037)

$scanBlock = {
    param($findings, $safeProcesses, $safePorts, $useVT, $vtKey, $deepScan)

    function Add-Finding {
        param([string]$Category,[string]$Severity,[string]$Description,[string]$Path="",[string]$Detail="")
        [void]$findings.Add([PSCustomObject]@{ Category=$Category; Severity=$Severity; Description=$Description; Path=$Path; Detail=$Detail })
    }

    function Test-Sig {
        param([string]$fp)
        if (-not $fp -or -not (Test-Path $fp -EA SilentlyContinue)) { return "NoFile" }
        try { return (Get-AuthenticodeSignature $fp -ErrorAction Stop).Status.ToString() } catch { return "Error" }
    }

    # 1. Malware file sizes
    foreach ($sp in @("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents","$env:APPDATA","$env:LOCALAPPDATA","$env:TEMP","$env:ProgramData")) {
        if (Test-Path $sp) { foreach ($sz in @(37308,37483)) { Get-ChildItem -Path $sp -Recurse -Depth 4 -Filter "*.exe" -EA SilentlyContinue | Where-Object { $_.Length -eq $sz } | ForEach-Object { Add-Finding "MALWARE_FILE" "CRITICAL" "Known malware size ($sz bytes)" $_.FullName "Created: $($_.LastWriteTime)" } } }
    }

    # 2. System masquerade
    foreach ($sp in @("$env:APPDATA","$env:LOCALAPPDATA","$env:TEMP","$env:USERPROFILE\Downloads")) {
        if (Test-Path $sp) { foreach ($nm in @("RuntimeBroker.exe","HealthService.exe","SecurityHealth.exe","svchost.exe","csrss.exe","lsass.exe","services.exe","dllhost.exe","conhost.exe","taskhostw.exe")) { Get-ChildItem -Path $sp -Recurse -Depth 4 -Filter $nm -EA SilentlyContinue | Where-Object { $_.FullName -notlike "*\Microsoft\Windows\*" } | ForEach-Object { if ($_.Directory -ne [System.IO.Path]::GetDirectoryName("$env:SystemRoot\System32\$nm")) { $sig=Test-Sig $_.FullName; $sev=if($sig -eq "Valid"){"MEDIUM"}else{"HIGH"}; Add-Finding "SYSTEM_MASQUERADE" $sev "System-named in user dir" $_.FullName "Signed: $sig" } } } }
    }

    # 3. Registry persistence
    foreach ($rp in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce")) {
        if (Test-Path $rp) { $pr=Get-ItemProperty -Path $rp -EA SilentlyContinue; if ($pr) { $pr.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" -and $_.Value } | ForEach-Object { $ep=($_.Value -split '"')[1]; if(-not $ep){$ep=($_.Value -split ' ')[0]}; $ep=$ep.Trim("'"); if($ep -and (Test-Path $ep -EA SilentlyContinue)){$iu=$ep -like "*\AppData*" -or $ep -like "*\Downloads*" -or $ep -like "*\Temp*"; $is=$ep -like "*\Windows\System32*" -or $ep -like "*\Windows\SysWOW64*"; if($iu -and -not $is){Add-Finding "REG_PERSIST" "HIGH" "Run key -> user dir" $rp "$($_.Name) -> $ep"}} } } }
    }
    foreach ($nm in @("RuntimeBroker","SecurityHealth","MicrosoftRuntimeBroker","HealthService")) { $v=(Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $nm -EA SilentlyContinue).$nm; if($v){Add-Finding "REG_PERSIST" "CRITICAL" "Known malware reg entry" "HKCU:\...\Run" "Entry: $nm = $v"} }

    # 4. Scheduled tasks
    foreach ($tn in @("MicrosoftRuntimeBroker","RuntimeBrokerHost","WMIRegistrationServices")) { $tk=Get-ScheduledTask -TaskName $tn -EA SilentlyContinue; if($tk){Add-Finding "SCHTASK_PERSIST" "CRITICAL" "Known malware task" $tn "Exec: $($tk.Actions.Execute)"} }
    Get-ScheduledTask | Where-Object { $_.TaskPath -eq "\" } | ForEach-Object { $a=$_.Actions.Execute; if($a -and ($a -like "*\AppData*" -or $a -like "*\Downloads*")){Add-Finding "SCHTASK_SUSPICIOUS" "MEDIUM" "Task from user dir" $_.TaskName "Exec: $a"} }

    # 5. Startup folder
    foreach ($sp in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")) { if(Test-Path $sp){Get-ChildItem -Path $sp -EA SilentlyContinue | ForEach-Object { if($_.Extension -in @(".exe",".com",".vbs",".js",".ps1",".bat",".cmd") -and $_.Extension -ne ".lnk"){Add-Finding "STARTUP_PERSIST" "HIGH" "Exe in Startup" $_.FullName "Size: $($_.Length)"} }} }

    # 6. COM hijacking
    foreach ($c in @("{42aedc87-2188-41fd-b9a3-0c966feab317}","{0D43FE01-F093-11CF-8940-00A0C9054228}","{F935DC22-1CF0-11D0-ADB9-00C04FD58A0B}")) { foreach($s in @("InprocServer32","LocalServer32")){$p="Registry::HKEY_CLASSES_ROOT\CLSID\$c\$s"; if(Test-Path $p){$v=(Get-ItemProperty -Path $p -EA SilentlyContinue).'(default)'; if($v -and ($v -like "*\AppData*" -or $v -like "*\Temp*")){Add-Finding "COM_HIJACK" "CRITICAL" "Known CLSID hijack" $c "Path: $v"}} } }

    # 7. Running processes
    Get-Process | Where-Object { $_.Path } | ForEach-Object { $proc=$_; $isS=@("RuntimeBroker","svchost","csrss","lsass","services","dllhost","conhost","taskhostw","SecurityHealth") -contains $proc.Name; if($isS -and -not($proc.Path -like "*\Windows\System32*" -or $proc.Path -like "*\Windows\SysWOW64*")){Add-Finding "PROCESS_ANOMALY" "CRITICAL" "Sys proc wrong loc" $proc.Path "PID: $($proc.Id)"}; if($proc.Path -and ($proc.Path -like "*\Downloads*" -or $proc.Path -like "*\AppData\Local\Temp*")){$sg=Test-Sig $proc.Path; if($sg -ne "Valid"){Add-Finding "PROCESS_UNSIGNED" "HIGH" "Unsigned from Downloads/Temp" $proc.Path "PID: $($proc.Id) | Sig: $sg"}} }

    # 8. RAT tools
    foreach ($r in @("AnyDesk","TeamViewer","UltraViewer","Ammyy Admin","DWAgent")) { Get-Process -Name ($r -replace "\.exe$","") -EA SilentlyContinue | ForEach-Object { if($_.Path -like "*\Downloads*"){Add-Finding "RAT_TOOL" "HIGH" "RAT from Downloads" $_.Path "PID: $($_.Id)"} }; Get-ChildItem "$env:USERPROFILE\Downloads" -Filter "$r.exe" -EA SilentlyContinue | ForEach-Object { Add-Finding "RAT_TOOL" "HIGH" "RAT in Downloads" $_.FullName } }

    if ($deepScan) {
        Get-Process | Where-Object { -not $_.Path -and $_.Name -and $_.Name -ne "" -and $_.Name -notin $safeProcesses } | ForEach-Object { Add-Finding "MEMORY_RESIDENT" "HIGH" "No disk path (fileless)" "PID: $($_.Id)" "Name: $($_.Name)" }
        Get-Process | Where-Object { $_.Path -and $_.Name -notin $safeProcesses } | ForEach-Object { try { $mm=$_.MainModule; if($mm -and $mm.FileName -and $_.Path -and $mm.FileName -ne $_.Path){Add-Finding "PROCESS_HOLLOW" "CRITICAL" "Hollowing detected" $_.Path "PID: $($_.Id) | Loaded: $($mm.FileName)"} } catch {} }
        Get-Process | Where-Object { $_.Path -and $_.Name -notin $safeProcesses } | ForEach-Object { $wm=[math]::Round($_.WorkingSet64/1MB,2); if($_.HandleCount -gt 2000){Add-Finding "HANDLE_ABUSE" "MEDIUM" "High handle count" $_.Path "PID: $($_.Id) | Handles: $($_.HandleCount) | WS: ${wm}MB"}; if($_.Threads.Count -gt 100){Add-Finding "THREAD_ABUSE" "MEDIUM" "High thread count" $_.Path "PID: $($_.Id) | Threads: $($_.Threads.Count)"} }
        Get-Process | Where-Object { $_.Path -and $_.Name -notin $safeProcesses } | ForEach-Object { if((Test-Sig $_.Path) -eq "Valid"){try{foreach($md in $_.Modules){$mp=$md.FileName; if($mp -and $mp -like "*.dll" -and ($mp -like "*\AppData*" -or $mp -like "*\Temp*" -or $mp -like "*\Downloads*")){$sk=$mp -like "*\Discord*" -or $mp -like "*\Spotify*" -or $mp -like "*\Brave*" -or $mp -like "*\Chrome*" -or $mp -like "*\Firefox*" -or $mp -like "*\Edge*" -or $mp -like "*\Steam*" -or $mp -like "*\Slack*"; if(-not $sk -and (Test-Sig $mp) -ne "Valid"){Add-Finding "DLL_INJECT" "HIGH" "Unsigned DLL in signed proc" $mp "Process: $($_.Name) PID: $($_.Id)"}}}}catch{}} }
        Get-NetTCPConnection -EA SilentlyContinue | Where-Object { $_.State -eq "Established" } | Group-Object OwningProcess | ForEach-Object { $proc=Get-Process -Id ([int]$_.Name) -EA SilentlyContinue; if($proc -and $proc.Path -and $proc.Name -notin @("svchost","chrome","brave","firefox","msedge","Discord","Spotify","Steam")){foreach($cn in $_.Group){if($cn.RemotePort -notin $safePorts){Add-Finding "UNUSUAL_PORT" "LOW" "Non-standard port" $proc.Path "PID: $($proc.Id) | Port: $($cn.RemotePort)"}}} }
        Get-Process | Where-Object { $_.Path } | ForEach-Object { if($_.MainWindowHandle -eq 0 -and $_.Path -like "*\AppData*" -and $_.Name -notin @("RuntimeBroker","SearchIndexer","Discord","Spotify","OneDrive","Code","ollama")){Add-Finding "HIDDEN_WINDOW" "MEDIUM" "Hidden AppData process" $_.Path "PID: $($_.Id) | Name: $($_.Name)"} }
    }

    if ($useVT -and $vtKey) {
        $findings | Where-Object { $_.Path -and (Test-Path $_.Path -EA SilentlyContinue) -and $_.Path -like "*.exe" } | Select-Object -First 10 | ForEach-Object {
            $h = (Get-FileHash $_.Path -Algorithm SHA256).Hash
            try { $rs=Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$h" -Headers @{ "x-apikey" = $vtKey } -Method GET -TimeoutSec 15; $st=$rs.data.attributes.last_analysis_stats; $ml=$st.malicious; $tt=($st.PSObject.Properties.Value | Measure-Object -Sum).Sum; if($ml -gt 0){ $_.Detail += " | VT: $ml/$tt detections"; $_.Description += " [VT: $ml engines detect]" } } catch {}
        }
    }
    return
}

# ══════════════════════════════════════════
# SCAN BUTTON
# ══════════════════════════════════════════
$btnScan.Add_Click({
    $script:findings = [System.Collections.ArrayList]::new()
    $btnScan.IsEnabled = $false
    $dgResults.ItemsSource = $null
    $txtStatus.Text = "Scanning..."
    $txtProgress.Text = "Running all checks..."
    $progressBar.Width = 10
    $txtCritical.Text="0"; $txtHigh.Text="0"; $txtMedium.Text="0"; $txtLow.Text="0"; $txtTotal.Text="Total: 0"
    $window.Cursor = [System.Windows.Input.Cursors]::Wait

    $useVT = $chkVT.IsChecked
    $deep = $chkDeepScan.IsChecked
    $vtKey = if ($useVT) { Load-VTKey } else { $null }

    # Run scan synchronously (window freezes briefly but scan completes reliably)
    try {
        & $scanBlock $script:findings $safeProcesses $safePorts $useVT $vtKey $deep
    } catch {
        $txtStatus.Text = "Error: $($_.Exception.Message)"
    }

    $window.Cursor = [System.Windows.Input.Cursors]::Arrow
    $crit = ($script:findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $hgh = ($script:findings | Where-Object { $_.Severity -eq "HIGH" }).Count
    $med = ($script:findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $low = ($script:findings | Where-Object { $_.Severity -eq "LOW" }).Count
    $txtCritical.Text = $crit.ToString()
    $txtHigh.Text = $hgh.ToString()
    $txtMedium.Text = $med.ToString()
    $txtLow.Text = $low.ToString()
    $txtTotal.Text = "Total: $($script:findings.Count)"
    $txtProgress.Text = "Scan complete"
    $maxW = $window.ActualWidth - 48
    $progressBar.Width = $maxW
    $dgResults.ItemsSource = @($script:findings)
    $btnExport.IsEnabled = $script:findings.Count -gt 0
    $btnClear.IsEnabled = $script:findings.Count -gt 0
    $btnScan.IsEnabled = $true
    $txtStatus.Text = "Scan complete - $($script:findings.Count) findings"
})

$btnExport.Add_Click({
    $dlg=New-Object Microsoft.Win32.SaveFileDialog; $dlg.Filter="CSV (*.csv)|*.csv"; $dlg.FileName="ioc-scan-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
    if($dlg.ShowDialog()){$script:findings | Export-Csv -Path $dlg.FileName -NoTypeInformation; $txtStatus.Text="Exported: $($dlg.FileName)"}
})

$btnClear.Add_Click({
    $script:findings=[System.Collections.ArrayList]::new(); $dgResults.ItemsSource=$null; $btnExport.IsEnabled=$false; $btnClear.IsEnabled=$false
    $txtCritical.Text="0"; $txtHigh.Text="0"; $txtMedium.Text="0"; $txtLow.Text="0"; $txtTotal.Text="Total: 0"
    $txtProgress.Text="Ready"; $txtTimer.Text=""; $progressBar.Width=0; $txtStatus.Text="Cleared."
})

$btnSettings.Add_Click({
    $dlg=New-Object System.Windows.Window; $dlg.Title="VirusTotal API Key"; $dlg.Width=450; $dlg.Height=250
    $dlg.Background=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#0d0d0d")
    $dlg.WindowStartupLocation="CenterOwner"; $dlg.Owner=$window
    $stack=New-Object System.Windows.Controls.StackPanel; $stack.Margin=[System.Windows.Thickness]::new(16)
    $lbl=New-Object System.Windows.Controls.TextBlock; $lbl.Text="VirusTotal API Key"; $lbl.Foreground=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#cc0000"); $lbl.FontSize=16; $lbl.FontWeight="Bold"; $stack.Children.Add($lbl)
    $desc=New-Object System.Windows.Controls.TextBlock; $desc.Text="Get free key at virustotal.com/community`nStored via Windows DPAPI."; $desc.Foreground=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#888"); $desc.FontSize=11; $desc.Margin=[System.Windows.Thickness]::new(0,4,0,12); $desc.TextWrapping="Wrap"; $stack.Children.Add($desc)
    $txtKey=New-Object System.Windows.Controls.TextBox; $txtKey.Height=28; $txtKey.FontSize=12; $saved=Load-VTKey; if($saved){$txtKey.Text=$saved}; $txtKey.Margin=[System.Windows.Thickness]::new(0,0,0,8); $stack.Children.Add($txtKey)
    $btnRow=New-Object System.Windows.Controls.StackPanel; $btnRow.Orientation="Horizontal"
    $btnSave=New-Object System.Windows.Controls.Button; $btnSave.Content="Save && Verify"; $btnSave.Height=30; $btnSave.Width=110; $btnSave.Background=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#1a1a2e"); $btnSave.Foreground="White"; $btnSave.BorderBrush=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#cc0000"); $btnSave.BorderThickness=[System.Windows.Thickness]::new(1); $btnSave.Margin=[System.Windows.Thickness]::new(0,0,8,0)
    $btnSave.Add_Click({ $key=$txtKey.Text.Trim(); if([string]::IsNullOrEmpty($key)){[System.Windows.MessageBox]::Show("Enter an API key","Error","OK","Error");return}; if(Test-VTApiKey -Key $key){Save-VTKey -ApiKey $key; $chkVT.IsEnabled=$true; $txtVTStatus.Text="VT API: Configured"; $txtVTStatus.Foreground=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#44cc44"); [System.Windows.MessageBox]::Show("Key saved!","Success","OK","Information"); $dlg.Close()}else{[System.Windows.MessageBox]::Show("Invalid key","Error","OK","Error")} })
    $btnRow.Children.Add($btnSave)
    $btnRemove=New-Object System.Windows.Controls.Button; $btnRemove.Content="Remove Key"; $btnRemove.Height=30; $btnRemove.Width=90; $btnRemove.Background=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#1a1a2e"); $btnRemove.Foreground="#cc4444"; $btnRemove.BorderBrush=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#333"); $btnRemove.BorderThickness=[System.Windows.Thickness]::new(1)
    $btnRemove.Add_Click({ Remove-VTKey; $txtKey.Text=""; $chkVT.IsEnabled=$false; $chkVT.IsChecked=$false; $txtVTStatus.Text="VT API: Not configured"; $txtVTStatus.Foreground=[System.Windows.Media.BrushConverter]::new().ConvertFromString("#cc4444"); [System.Windows.MessageBox]::Show("Key removed","Removed","OK","Information") })
    $btnRow.Children.Add($btnRemove)
    $stack.Children.Add($btnRow); $dlg.Content=$stack; $dlg.ShowDialog() | Out-Null
})

$window.Add_Loaded({ $txtStatus.Text="Ready. Click Start Scan. Deep Scan includes memory analysis, process hollowing, and network checks." })
[void]$window.ShowDialog()
