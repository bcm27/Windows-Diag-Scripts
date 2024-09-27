# Requires -RunAsAdministrator

# Function to create a timestamped log file
function Start-Logging {
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $scriptPath = $PSScriptRoot
    $logPath = Join-Path $scriptPath "../logs/WindowsDiagnostics_$timestamp.log"
    try {
        Start-Transcript -Path $logPath -ErrorAction Stop
        Write-Host "Logging started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
        Write-Host "Log file: $logPath" -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to start logging: $_" -ForegroundColor Red
    }
}

# Function to stop logging
function Stop-Logging {
    try {
        Stop-Transcript
        Write-Host "Logging stopped at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to stop logging: $_" -ForegroundColor Red
    }
}

# Function to get system information
function Get-SystemInfo {
    Write-Host "Gathering system information..." -ForegroundColor Yellow
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $cpu = Get-CimInstance Win32_Processor
        $ram = Get-CimInstance Win32_PhysicalMemory
        $gpu = Get-CimInstance Win32_VideoController
        
        # Calculate total RAM
        $totalRAM = ($ram | Measure-Object -Property Capacity -Sum).Sum
        
        # Get RAM speed and type
        $ramSpeed = $ram[0].Speed
        $ramType = switch ($ram[0].SMBIOSMemoryType) {
            20 {"DDR"}
            21 {"DDR2"}
            22 {"DDR2 FB-DIMM"}
            24 {"DDR3"}
            26 {"DDR4"}
            default {"Unknown"}
        }
        
        # Determine GPU type and info
        $gpuInfo = if ($gpu.Count -gt 1) {
            $dedicatedGPU = $gpu | Where-Object { $_.AdapterCompatibility -notmatch "Intel|AMD" -and $_.VideoProcessor -notmatch "Intel|AMD" } | Select-Object -First 1
            if ($dedicatedGPU) {
                "Dedicated GPU: $($dedicatedGPU.Name) ($($dedicatedGPU.AdapterRAM / 1GB) GB)"
            } else {
                "Multiple GPUs: " + ($gpu.Name -join ", ")
            }
        } elseif ($gpu.AdapterCompatibility -match "Intel|AMD" -or $gpu.VideoProcessor -match "Intel|AMD") {
            "Integrated Graphics: $($gpu.Name)"
        } else {
            "Dedicated GPU: $($gpu.Name) ($($gpu.AdapterRAM / 1GB) GB)"
        }
        
        [PSCustomObject]@{
            "OS Name"             = $os.Caption
            "OS Version"          = $os.Version
            "CPU"                 = $cpu.Name
            "RAM (GB)"            = [math]::Round($totalRAM / 1GB, 2)
            "RAM Type"            = $ramType
            "RAM Speed (MHz)"     = $ramSpeed
            "Graphics"            = $gpuInfo
            "Last Boot Time"      = $os.LastBootUpTime
        } | Format-List
    } catch {
        Write-Host "Failed to gather system information: $_" -ForegroundColor Red
    }
}

# Function to check disk health and space
function Check-DiskHealth {
    Write-Host "Checking disk health and space..." -ForegroundColor Yellow
    try {
        $physicalDisks = Get-PhysicalDisk | ForEach-Object {
            [PSCustomObject]@{
                Number            = $_.DeviceId
                MediaType         = $_.MediaType
                HealthStatus      = $_.HealthStatus
                OperationalStatus = $_.OperationalStatus
            }
        }

        $bootVolume = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive

        Get-Volume | Where-Object { $null -ne $_.DriveLetter } | ForEach-Object {
            $volume = $_
            $partition = Get-Partition -Volume $volume -ErrorAction SilentlyContinue
            $physicalDisk = if ($partition) { $physicalDisks | Where-Object { $_.Number -eq $partition.DiskNumber } } else { $null }

            [PSCustomObject]@{
                "Drive Letter"       = $volume.DriveLetter
                "Label"              = if ($volume.DriveLetter -eq $bootVolume[0] -and [string]::IsNullOrWhiteSpace($volume.FileSystemLabel)) { "System" } else { $volume.FileSystemLabel }
                "File System"        = $volume.FileSystem
                "Media Type"         = if ($physicalDisk) { $physicalDisk.MediaType } else { "Unknown" }
                "Health Status"      = if ($physicalDisk) { $physicalDisk.HealthStatus } else { "N/A" }
                "Operational Status" = if ($physicalDisk) { $physicalDisk.OperationalStatus } else { $volume.OperationalStatus }
                "Total Size (GB)"    = [math]::Round($volume.Size / 1GB, 2)
                "Free Space (GB)"    = [math]::Round($volume.SizeRemaining / 1GB, 2)
                "Free Space (%)"     = if ($volume.Size -gt 0) { [math]::Round(($volume.SizeRemaining / $volume.Size) * 100, 2) } else { "N/A" }
            }
        } | Format-Table -AutoSize
    } catch {
        Write-Host "Failed to check disk health: $_" -ForegroundColor Red
    }
}

# Function to check Windows Update status
function Check-WindowsUpdate {
    Write-Host "Checking Windows Update status..." -ForegroundColor Yellow
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $pendingUpdates = $updateSearcher.Search("IsInstalled=0").Updates

        Write-Host "Pending updates: $($pendingUpdates.Count)"
        if ($pendingUpdates.Count -gt 0) {
            $pendingUpdates | ForEach-Object {
                [PSCustomObject]@{
                    "Title"      = $_.Title
                    "KB Article" = $_.KBArticleIDs -join ', '
                    "Severity"   = $_.MsrcSeverity
                }
            } | Format-Table -AutoSize
        }
    } catch {
        Write-Host "Failed to check Windows Update status: $_" -ForegroundColor Red
    }
}

# Function to check running processes
function Check-Processes {
    Write-Host "Checking top CPU and Memory consuming processes..." -ForegroundColor Yellow
    try {
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | 
        Format-Table -Property ProcessName, CPU, @{Name = "Memory(MB)"; Expression = { [math]::Round($_.WS / 1MB, 2) } }, Id -AutoSize
    } catch {
        Write-Host "Failed to check processes: $_" -ForegroundColor Red
    }
}

# Function to check critical services
function Check-Services {
    Write-Host "Checking critical services..." -ForegroundColor Yellow
    $criticalServices = @('wuauserv', 'WinDefend', 'MpsSvc', 'EventLog', 'Dnscache', 'DHCP')
    try {
        Get-Service $criticalServices | ForEach-Object {
            [PSCustomObject]@{
                "Service Name" = $_.Name
                "Display Name" = $_.DisplayName
                "Status"       = $_.Status
                "Start Type"   = $_.StartType
            }
        } | Format-Table -AutoSize
    } catch {
        Write-Host "Failed to check critical services: $_" -ForegroundColor Red
    }
}

# Function to check network connectivity
function Check-NetworkConnectivity {
    Write-Host "Checking network connectivity..." -ForegroundColor Yellow
    $pingTarget = "www.google.com"
    try {
        $testResults = Test-NetConnection $pingTarget -ErrorAction SilentlyContinue

        if ($testResults) {
            [PSCustomObject]@{
                "ComputerName"      = $testResults.ComputerName
                "RemoteAddress"     = $testResults.RemoteAddress
                "InterfaceAlias"    = $testResults.InterfaceAlias
                "SourceAddress"     = $testResults.SourceAddress
                "PingSucceeded"     = $testResults.PingSucceeded
                "PingRoundtripTime" = if ($testResults.PingSucceeded -and $testResults.PingReplyDetails) { 
                    $testResults.PingReplyDetails.RoundtripTime 
                } elseif ($testResults.PingSucceeded) {
                    "Succeeded but time not available"
                } else {
                    "N/A - Ping Failed"
                }
            } | Format-List

            # Additional ping test
            Write-Host "Performing additional ping test..." -ForegroundColor Yellow
            $pingResults = Test-Connection -ComputerName $pingTarget -Count 4 -ErrorAction SilentlyContinue
            if ($pingResults) {
                $pingResults | Select-Object @{Name = "Address"; Expression = { $_.Address } }, 
                @{Name = "Roundtrip time (ms)"; Expression = { $_.Latency } }, 
                @{Name = "Status"; Expression = { $_.Status } } |
                Format-Table -AutoSize
            } else {
                Write-Host "Additional ping test failed or returned no results." -ForegroundColor Red
            }
        } else {
            Write-Host "Unable to perform network connectivity test. Check your internet connection." -ForegroundColor Red
        }

        Write-Host "Network Adapter Information:" -ForegroundColor Yellow
        Get-NetAdapter | Where-Object Status -eq "Up" | Format-Table -Property Name, InterfaceDescription, Status, LinkSpeed -AutoSize
    } catch {
        Write-Host "Failed to check network connectivity: $_" -ForegroundColor Red
    }
}

# Function to check system file integrity
function Check-SystemFileIntegrity {
    Write-Host "Checking system file integrity..." -ForegroundColor Yellow
    Write-Host "This may take some time. Please be patient." -ForegroundColor Yellow

    try {
        # Run SFC
        Write-Host "Running System File Checker (SFC)..." -ForegroundColor Yellow
        $sfcOutput = & sfc /scannow | Out-String

        if ($sfcOutput -match "Windows Resource Protection did not find any integrity violations.") {
            Write-Host "System File Checker completed successfully. No integrity violations found." -ForegroundColor Green
        } elseif ($sfcOutput -match "Windows Resource Protection found corrupt files and successfully repaired them.") {
            Write-Host "System File Checker found and repaired corrupt files." -ForegroundColor Yellow
        } elseif ($sfcOutput -match "Windows Resource Protection found corrupt files but was unable to fix some of them.") {
            Write-Host "System File Checker found corrupt files but couldn't repair all of them. Further investigation may be needed." -ForegroundColor Red
        } else {
            Write-Host "System File Checker completed, but the output is inconclusive. Please review the CBS log file for more details." -ForegroundColor Yellow
        }

        # Run DISM to check for and repair Windows image
        Write-Host "Running DISM to check for and repair Windows image..." -ForegroundColor Yellow
        $dismScanOutput = & dism /Online /Cleanup-Image /ScanHealth 2>&1 | Out-String
        if ($dismScanOutput -match "No component store corruption detected.") {
            Write-Host "DISM scan completed. No corruption detected." -ForegroundColor Green
        } elseif ($dismScanOutput -match "The operation completed successfully.") {
            Write-Host "DISM scan completed. Please review the full output for any warnings." -ForegroundColor Yellow
        } else {
            Write-Host "DISM encountered issues during the scan:" -ForegroundColor Red
            Write-Host $dismScanOutput -ForegroundColor Red
            Write-Host "Attempting repair operation..." -ForegroundColor Yellow
            
            $dismRepairOutput = & dism /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String
            if ($dismRepairOutput -match "The restore operation completed successfully.") {
                Write-Host "DISM successfully repaired the Windows image." -ForegroundColor Green
            } else {
                Write-Host "DISM encountered issues during repair:" -ForegroundColor Red
                Write-Host $dismRepairOutput -ForegroundColor Red
                Write-Host "Manual intervention may be required. Consider the following steps:" -ForegroundColor Yellow
                Write-Host "1. Run 'DISM /Online /Cleanup-Image /RestoreHealth /Source:<path_to_install_media> /LimitAccess' with a known good source." -ForegroundColor Yellow
                Write-Host "2. If the issue persists, you may need to perform an in-place upgrade or reset of Windows." -ForegroundColor Yellow
            }
        }

        # Check Windows Update Health
        Write-Host "Checking Windows Update health..." -ForegroundColor Yellow
        try {
            $updateLogPath = "$env:TEMP\WindowsUpdate.log"
            $null = Get-WindowsUpdateLog -LogPath $updateLogPath
            Write-Host "Windows Update log generated successfully at $updateLogPath. Please review it for any issues." -ForegroundColor Green
        } catch {
            Write-Host "Failed to generate Windows Update log: $_" -ForegroundColor Red
            Write-Host "There might be issues with Windows Update. Consider running 'sfc /scannow' and then 'DISM /Online /Cleanup-Image /RestoreHealth' manually." -ForegroundColor Yellow
        }

    } catch {
        Write-Host "An error occurred during system file integrity check: $_" -ForegroundColor Red
    }

    Write-Host "System file integrity check completed." -ForegroundColor Yellow
    Write-Host "If issues persist, consider the following steps:" -ForegroundColor Yellow
    Write-Host "1. Review the CBS log file at C:\Windows\Logs\CBS\CBS.log" -ForegroundColor Yellow
    Write-Host "2. Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth' manually" -ForegroundColor Yellow
    Write-Host "3. If problems continue, consider performing an in-place upgrade of Windows" -ForegroundColor Yellow
}

# Function to check for virus and malware
function Check-VirusAndMalware {
    Write-Host "Performing comprehensive virus and malware check..." -ForegroundColor Yellow

    $activities = @(
        "Checking Windows Defender Status",
        "Detecting Third-party Antivirus",
        "Running Selected Scan",
        "Retrieving Threat History",
        "Performing Additional Security Checks"
    )

    for ($i = 0; $i -lt $activities.Count; $i++) {
        $activity = $activities[$i]
        $percentComplete = [math]::Round(($i / $activities.Count) * 100)
        
        Write-Progress -Activity "Virus and Malware Check" -Status $activity -PercentComplete $percentComplete

        switch ($activity) {
            "Checking Windows Defender Status" {
                $defenderStatus = Get-MpComputerStatus
                Write-Host "Windows Defender Status:" -ForegroundColor Cyan
                [PSCustomObject]@{
                    "Real-time Protection"           = $defenderStatus.RealTimeProtectionEnabled
                    "Antivirus Signature Version"    = $defenderStatus.AntivirusSignatureVersion
                    "Antivirus Signature Age (Days)" = $defenderStatus.AntivirusSignatureAge
                    "Last Quick Scan Date"           = $defenderStatus.QuickScanEndTime
                    "Last Full Scan Date"            = $defenderStatus.FullScanEndTime
                } | Format-List
            }
            "Detecting Third-party Antivirus" {
                $antivirusSoftware = @(
                    @{Name="Norton"; Path="HKLM:\SOFTWARE\Norton"},
                    @{Name="McAfee"; Path="HKLM:\SOFTWARE\McAfee"},
                    @{Name="Kaspersky"; Path="HKLM:\SOFTWARE\Kaspersky Lab"},
                    @{Name="Bitdefender"; Path="HKLM:\SOFTWARE\BITDEFENDER"},
                    @{Name="Avast"; Path="HKLM:\SOFTWARE\AVAST Software"},
                    @{Name="AVG"; Path="HKLM:\SOFTWARE\AVG"}
                )
                $installedAntivirus = $antivirusSoftware | Where-Object { Test-Path $_.Path }
                if ($installedAntivirus) {
                    Write-Host "Detected third-party antivirus software:" -ForegroundColor Green
                    $installedAntivirus | ForEach-Object { Write-Host "- $($_.Name)" }
                } else {
                    Write-Host "No third-party antivirus software detected." -ForegroundColor Yellow
                }
            }
            "Running Selected Scan" {
                $scanOptions = @("Windows Defender Quick Scan", "Windows Defender Full Scan")
                if ($installedAntivirus) {
                    $scanOptions += "Third-party Antivirus Scan"
                }
                $scanOptions += "Skip Scan"

                $scanChoice = $scanOptions | Out-GridView -Title "Select scan option" -PassThru

                switch ($scanChoice) {
                    "Windows Defender Quick Scan" { 
                        Write-Host "Starting Windows Defender Quick Scan..." -ForegroundColor Cyan
                        Start-MpScan -ScanType QuickScan
                        Wait-ForScanCompletion -ScanType "Quick" 
                    }
                    "Windows Defender Full Scan" { 
                        Write-Host "Starting Windows Defender Full Scan..." -ForegroundColor Cyan
                        Start-MpScan -ScanType FullScan
                        Wait-ForScanCompletion -ScanType "Full" 
                    }
                    "Third-party Antivirus Scan" {
                        Write-Host "Please run a scan using your installed third-party antivirus software: $($installedAntivirus.Name)" -ForegroundColor Yellow
                        Write-Host "Consult the software's documentation for instructions on running a scan." -ForegroundColor Yellow
                        Read-Host "Press Enter when you have completed the third-party scan"
                    }
                    "Skip Scan" { Write-Host "Scan skipped." -ForegroundColor Yellow }
                    $null { Write-Host "Scan selection cancelled." -ForegroundColor Yellow }
                }
            }
            "Retrieving Threat History" {
                $threats = Get-MpThreatDetection
                if ($threats) {
                    Write-Host "Recent threats detected:" -ForegroundColor Yellow
                    $threats | Select-Object -First 10 | ForEach-Object {
                        [PSCustomObject]@{
                            "Threat Name"    = $_.ThreatName
                            "Detection Time" = $_.InitialDetectionTime
                            "Status"         = $_.ThreatStatusName
                            "Resources"      = ($_.Resources -join ', ')
                        }
                    } | Format-Table -AutoSize
                } else {
                    Write-Host "No threats detected in the history." -ForegroundColor Green
                }
            }
            "Performing Additional Security Checks" {
                # Check for potentially unwanted applications (PUA)
                $puaProtection = Get-MpPreference | Select-Object -ExpandProperty PUAProtection
                if ($null -eq $puaProtection) {
                    Write-Host "Unable to determine PUA Protection status." -ForegroundColor Yellow
                } elseif ($puaProtection -eq 2) {
                    Write-Host "PUA Protection is fully enabled." -ForegroundColor Green
                } elseif ($puaProtection -eq 1) {
                    Write-Host "PUA Protection is enabled in audit mode. Consider enabling full blocking for better protection." -ForegroundColor Yellow
                } elseif ($puaProtection -eq 0) {
                    Write-Host "PUA Protection is disabled. Consider enabling it for better protection." -ForegroundColor Red
                } else {
                    Write-Host "Unexpected PUA Protection value: $puaProtection. Please verify your settings." -ForegroundColor Yellow
                }

                # Check for suspicious connections
                Write-Host "Checking for suspicious network connections..." -ForegroundColor Cyan
                $suspiciousConnections = Get-NetTCPConnection | Where-Object { 
                    $_.State -eq 'Established' -and 
                    $_.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' -and
                    $_.RemoteAddress -ne '127.0.0.1' -and
                    $_.RemoteAddress -ne '::1'
                }
                if ($suspiciousConnections) {
                    Write-Host "Suspicious connections detected:" -ForegroundColor Yellow
                    Write-Host "Note: this is a list of processes transmitting data from your computer."
                    Write-Host "It by default does not mean a program is a malicious one."
                    $suspiciousConnections | ForEach-Object {
                        [PSCustomObject]@{
                            "Local Address"  = $_.LocalAddress
                            "Local Port"     = $_.LocalPort
                            "Remote Address" = $_.RemoteAddress
                            "Remote Port"    = $_.RemotePort
                            "Process ID"     = $_.OwningProcess
                            "Process Name"   = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                        }
                    } | Format-Table -AutoSize
                } else {
                    Write-Host "No suspicious network connections detected." -ForegroundColor Green
                }
            }
        }
    }

    Write-Progress -Activity "Virus and Malware Check" -Completed
}

function Wait-ForScanCompletion {
    param (
        [string]$ScanType
    )

    $timeout = if ($ScanType -eq "Quick") { 900 } else { 3600 } # 15 minutes for Quick, 1 hour for Full
    $timer = [Diagnostics.Stopwatch]::StartNew()

    while (($scan = Get-MpComputerStatus)."${ScanType}ScanAge" -eq 0 -and $timer.Elapsed.TotalSeconds -lt $timeout) {
        $elapsedSeconds = [math]::Round($timer.Elapsed.TotalSeconds)
        $percentComplete = [math]::Min(100, [math]::Round(($elapsedSeconds / $timeout) * 100))
        
        Write-Progress -Activity "Running $ScanType Scan" -Status "Time Elapsed: $elapsedSeconds seconds" -PercentComplete $percentComplete
        
        Start-Sleep -Seconds 1
    }
    $timer.Stop()

    Write-Progress -Activity "Running $ScanType Scan" -Completed

    if ($scan."${ScanType}ScanAge" -eq 0) {
        Write-Host "Scan timed out. Please check Windows Security for full results." -ForegroundColor Red
    } else {
        Write-Host "${ScanType} scan completed." -ForegroundColor Green
        Write-Host "Last ${ScanType} Scan Date: $($scan."${ScanType}ScanEndTime")" -ForegroundColor Cyan
    }
}

# Function to check for common security issues
function Check-SecurityIssues {
    Write-Host "Checking for common security issues..." -ForegroundColor Yellow
    try {
        # Check Windows Defender status
        $defenderStatus = Get-MpComputerStatus
        Write-Host "Windows Defender Status:" -ForegroundColor Cyan
        [PSCustomObject]@{
            "Real-time Protection" = $defenderStatus.RealTimeProtectionEnabled
            "Antivirus Signature"  = "$($defenderStatus.AntispywareSignatureVersion) (Age: $($defenderStatus.AntispywareSignatureAge) days)"
        } | Format-List

        # Check firewall status
        $firewallProfiles = Get-NetFirewallProfile
        Write-Host "Firewall Status:" -ForegroundColor Cyan
        $firewallProfiles | ForEach-Object {
            [PSCustomObject]@{
                "Profile" = $_.Name
                "Enabled" = $_.Enabled
            }
        } | Format-Table -AutoSize

        # Check for pending reboots
        $pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        Write-Host "Pending Reboot: $pendingReboot" -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to check security issues: $_" -ForegroundColor Red
    }
}

function Reset-NetworkSettings {
    # Check for administrator privileges
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "This function requires administrator privileges. Please run PowerShell as an administrator."
        return
    }

    Write-Host "Resetting network settings..." -ForegroundColor Yellow

    try {
        # Reset network adapters
        Write-Host "Resetting network adapters..." -ForegroundColor Yellow
        Get-NetAdapter | Restart-NetAdapter

        # Release and renew IP configuration
        Write-Host "Releasing and renewing IP configuration..." -ForegroundColor Yellow
        ipconfig /release
        ipconfig /renew

        # Reset Winsock
        Write-Host "Resetting Winsock..." -ForegroundColor Yellow
        netsh winsock reset

        # Clear DNS cache
        Write-Host "Clearing DNS cache..." -ForegroundColor Yellow
        ipconfig /flushdns

        # Reset TCP/IP stack
        Write-Host "Resetting TCP/IP stack..." -ForegroundColor Yellow
        netsh int ip reset

        Write-Host "Network settings have been reset successfully. A system restart is recommended for changes to take full effect." -ForegroundColor Green
    }
    catch {
        Write-Host "An error occurred while resetting network settings: $_" -ForegroundColor Red
    }
}

# Function to get performance metrics
function Get-PerformanceMetrics {
    Write-Host "Gathering performance metrics..." -ForegroundColor Yellow
    try {
        $cpu = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        $memory = Get-Counter '\Memory\% Committed Bytes In Use'
        $disk = Get-Counter '\PhysicalDisk(_Total)\% Disk Time'
        $network = Get-Counter '\Network Interface(*)\Bytes Total/sec'

        [PSCustomObject]@{
            "CPU Usage (%)"       = [math]::Round($cpu, 2)
            "Memory Usage (%)"    = [math]::Round($memory.CounterSamples.CookedValue, 2)
            "Disk Usage (%)"      = [math]::Round($disk.CounterSamples.CookedValue, 2)
            "Network Usage (B/s)" = [math]::Round(($network.CounterSamples | Measure-Object -Property CookedValue -Sum).Sum, 2)
        } | Format-List
    } catch {
        Write-Host "Failed to gather performance metrics: $_" -ForegroundColor Red
    }
}

# Function to run a single test
function Invoke-SingleTest {
    param (
        [string]$TestNumber
    )
    switch ($TestNumber) {
        "1" { Get-SystemInfo }
        "2" { Check-DiskHealth }
        "3" { Check-WindowsUpdate }
        "4" { Check-Processes }
        "5" { Check-Services }
        "6" { Check-NetworkConnectivity }
        "7" { Check-SystemFileIntegrity }
        "8" { Check-SecurityIssues }
        "9" { Check-VirusAndMalware }
        "10" { Get-PerformanceMetrics }
        "11" { Reset-NetworkSettings }
    }
}

function Invoke-SelectedTests {
    param (
        [string[]]$TestsToRun
    )

    $totalTests = $TestsToRun.Count
    for ($i = 0; $i -lt $totalTests; $i++) {
        $testNumber = $TestsToRun[$i]
        $testName = Get-TestName -TestNumber $testNumber
        
        $percentComplete = [math]::Round(($i / $totalTests) * 100)
        $statusMessage = [string]::Format("Test {0} of {1}: {2}", $testNumber, $totalTests, $testName)
        Write-Progress -Activity "Running Diagnostic Tests" -Status $statusMessage -PercentComplete $percentComplete

        Invoke-SingleTest -TestNumber $testNumber
    }
    Write-Progress -Activity "Running Diagnostic Tests" -Completed
}

function Show-Menu {
    Clear-Host
    Write-Host "================ Windows Diagnostics Tool ================" -ForegroundColor Cyan
    Write-Host "1: Check System Information"
    Write-Host "2: Check Disk Health"
    Write-Host "3: Check Windows Update Status"
    Write-Host "4: List Running Processes"
    Write-Host "5: List Critical Services"
    Write-Host "6: Check Network Connectivity"
    Write-Host "7: Run System File Integrity"
    Write-Host "8: Check Security Settings"
    Write-Host "9: Run Virus and Malware Scans"
    Write-Host "10: Run Performance Metrics"
    Write-Host "11: Reset Network Settings and DNS Cache"
    Write-Host "12: Check for Driver Updates"
    Write-Host "13: Analyze System Boot Performance"
    Write-Host "14: Check Power Usage and Battery Health"
    Write-Host "================ Test Groups ================" -ForegroundColor Cyan
    Write-Host "A: Run All Tests"
    Write-Host "B: Run All Tests Except Security and Networking"
    Write-Host "C: Run Only Security Tests"
    Write-Host "D: Run Only Networking Tests"
    Write-Host "S: Run Standard Tests (No Security or Networking)"
    Write-Host "Q: Quit"
    Write-Host "=======================================================" -ForegroundColor Cyan
    $selection = Read-Host "Enter your selection"
    return $selection
}

function Get-TestName {
    param (
        [string]$TestNumber
    )
    
    switch ($TestNumber) {
        "1" { return "System Information" }
        "2" { return "Disk Health" }
        "3" { return "Windows Update Status" }
        "4" { return "Running Processes" }
        "5" { return "Critical Services" }
        "6" { return "Network Connectivity" }
        "7" { return "System File Integrity" }
        "8" { return "Security Issues" }
        "9" { return "Virus and Malware Check" }
        "10" { return "Performance Metrics" }
        "11" { return "Reset Network Settings and DNS Cache" }
        "12" { return "Driver Updates" }
        "13" { return "Boot Performance" }
        "14" { return "Power Usage and Battery Health" }
        default { return "Unknown Test" }
    }
}

# Main execution
try {
    Start-Logging
    $continue = $true
    $selectedTests = @()

    while ($continue) {
        $choice = Show-Menu

        switch ($choice) {
            { '1'..'14' -contains $_ } {
                if ($selectedTests -notcontains $_) {
                    $selectedTests += $_
                }
            }
            'A' { 
                $selectedTests = '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14'
                $continue = $false
            }
            'B' { 
                $selectedTests = '1', '2', '3', '4', '5', '7', '10', '12', '13', '14'
                $continue = $false
            }
            'C' { 
                $selectedTests = '8', '9'
                $continue = $false
            }
            'D' { 
                $selectedTests = '6', '11'
                $continue = $false
            }
            'S' { 
                $selectedTests = '1', '2', '3', '4', '5', '7', '10', '12', '13', '14'
                $continue = $false
            }
            'Q' { 
                if ($selectedTests.Count -eq 0) {
                    $continue = $false
                } else {
                    $runTests = Read-Host "Do you want to run the selected tests before quitting? (Y/N)"
                    if ($runTests -eq 'Y') {
                        $continue = $false
                    } else {
                        Write-Host "Exiting without running tests." -ForegroundColor Yellow
                        exit
                    }
                }
            }
            default { Write-Host "Invalid selection. Please try again." -ForegroundColor Red }
        }

        if ($continue -and $selectedTests.Count -gt 0) {
            $runNow = Read-Host "Do you want to run the selected tests now? (Y/N)"
            if ($runNow -eq 'Y') {
                $continue = $false
            }
        }
    }

    if ($selectedTests.Count -gt 0) {
        Write-Host "Running selected tests..." -ForegroundColor Green
        Invoke-SelectedTests -TestsToRun $selectedTests
    }

    Write-Host "Diagnostics completed successfully. Please review the log file for detailed results." -ForegroundColor Green

} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
} finally {
    Stop-Logging
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")