# Requires -RunAsAdministrator

# Function to create a timestamped log file
function Start-Logging {
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $logPath = "$env:USERPROFILE\Desktop\WindowsDiagnostics_$timestamp.log"
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

# Function to display the menu and get user selection
function Show-Menu {
    Clear-Host
    Write-Host "================ Windows Diagnostics Tool ================" -ForegroundColor Cyan
    Write-Host "1: System Information"
    Write-Host "2: Disk Health"
    Write-Host "3: Windows Update Status"
    Write-Host "4: Running Processes"
    Write-Host "5: Critical Services"
    Write-Host "6: Network Connectivity"
    Write-Host "7: System File Integrity"
    Write-Host "8: Security Issues"
    Write-Host "9: Virus and Malware Check"
    Write-Host "10: Performance Metrics"
    Write-Host "R: Run All Tests"
    Write-Host "S: Run without Security Tests"
    Write-Host "Q: Quit"
    Write-Host "=======================================================" -ForegroundColor Cyan
    $selection = Read-Host "Enter your selection"
    return $selection
}

# Function to get system information
function Get-SystemInfo {
    Write-Host "Gathering system information..." -ForegroundColor Yellow
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $cpu = Get-CimInstance Win32_Processor
        $ram = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
        [PSCustomObject]@{
            "OS Name"             = $os.Caption
            "OS Version"          = $os.Version
            "System Manufacturer" = $cs.Manufacturer
            "System Model"        = $cs.Model
            "CPU"                 = $cpu.Name
            "RAM (GB)"            = [math]::Round($ram.Sum / 1GB, 2)
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
    Write-Host "This may take some time..."
    try {
        $sfc = Start-Process -FilePath "sfc" -ArgumentList "/scannow" -Wait -PassThru -Verb RunAs
        if ($sfc.ExitCode -eq 0) {
            Write-Host "System File Checker completed successfully." -ForegroundColor Green
        } else {
            Write-Host "System File Checker encountered an issue. Exit code: $($sfc.ExitCode)" -ForegroundColor Red
        }
    } catch {
        Write-Host "Failed to check system file integrity: $_" -ForegroundColor Red
    }
}

# Function to check for virus and malware
function Check-VirusAndMalware {
    Write-Host "Performing enhanced virus and malware check..." -ForegroundColor Yellow
    try {
        # Check Windows Defender status
        $defenderStatus = Get-MpComputerStatus
        Write-Host "Windows Defender Status:" -ForegroundColor Cyan
        [PSCustomObject]@{
            "Real-time Protection"           = $defenderStatus.RealTimeProtectionEnabled
            "Antivirus Signature Version"    = $defenderStatus.AntivirusSignatureVersion
            "Antivirus Signature Age (Days)" = $defenderStatus.AntivirusSignatureAge
            "Last Full Scan Date"            = $defenderStatus.FullScanEndTime
            "Quick Scan Age (Days)"          = $defenderStatus.QuickScanAge
        } | Format-List

        # Perform a quick scan
        Write-Host "Initiating a quick scan with Windows Defender..." -ForegroundColor Cyan
        Start-MpScan -ScanType QuickScan

        # Wait for the scan to complete (with timeout)
        $timeout = 300 # 5 minutes timeout
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (($scan = Get-MpComputerStatus).QuickScanAge -eq 0 -and $timer.Elapsed.TotalSeconds -lt $timeout) {
            Write-Host "Scan in progress... Please wait." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
        $timer.Stop()

        if ($scan.QuickScanAge -eq 0) {
            Write-Host "Scan timed out. Please check Windows Security for full results." -ForegroundColor Red
        } else {
            Write-Host "Quick scan completed." -ForegroundColor Green
        }

        # Get threat history
        Write-Host "Retrieving threat history..." -ForegroundColor Cyan
        $threats = Get-MpThreatDetection
        if ($threats) {
            $threats | ForEach-Object {
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

        # Check for potentially unwanted applications (PUA)
        Write-Host "Checking for potentially unwanted applications..." -ForegroundColor Cyan
        $puaProtection = Get-MpPreference | Select-Object -ExpandProperty PUAProtection
        if ($puaProtection -eq 2) {
            Write-Host "PUA Protection is enabled." -ForegroundColor Green
        } else {
            Write-Host "PUA Protection is not fully enabled. Consider enabling it for better protection." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Failed to check for viruses and malware: $_" -ForegroundColor Red
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
    }
}

# Function to run selected tests
function Invoke-SelectedTests {
    param (
        [string[]]$TestsToRun
    )
    for ($i = 0; $i -lt $TestsToRun.Count; $i++) {
        $progress = @{
            Activity        = "Running Diagnostic Tests"
            Status          = "Processing Test $($TestsToRun[$i])"
            PercentComplete = ($i / $TestsToRun.Count) * 100
        }
        Write-Progress @progress
        Invoke-SingleTest -TestNumber $TestsToRun[$i]
    }
    Write-Progress -Activity "Running Diagnostic Tests" -Completed
}

# Main execution
try {
    Start-Logging
    $continue = $true
    $selectedTests = @()

    while ($continue) {
        $choice = Show-Menu

        switch ($choice) {
            { '1'..'10' -contains $_ } {
                if ($selectedTests -notcontains $_) {
                    $selectedTests += $_
                }
            }
            'R' { 
                $selectedTests = '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'
                $continue = $false
            }
            'S' { 
                $selectedTests = '1', '2', '3', '4', '5', '6', '7'
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

        if ($continue) {
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
