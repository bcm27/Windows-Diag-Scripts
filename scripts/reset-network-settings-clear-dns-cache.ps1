# Requires administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You need to run this script as an Administrator. Right-click the PowerShell icon and select 'Run as administrator'."
    break
}

# Function to reset network adapters
function Reset-NetworkAdapters {
    Write-Host "Resetting network adapters..." -ForegroundColor Yellow
    Get-NetAdapter | Restart-NetAdapter
}

# Function to release and renew IP configuration
function Reset-IPConfig {
    Write-Host "Releasing and renewing IP configuration..." -ForegroundColor Yellow
    ipconfig /release
    ipconfig /renew
}

# Function to reset Winsock
function Reset-Winsock {
    Write-Host "Resetting Winsock..." -ForegroundColor Yellow
    netsh winsock reset
}

# Function to clear DNS cache
function Clear-DNSCache {
    Write-Host "Clearing DNS cache..." -ForegroundColor Yellow
    ipconfig /flushdns
}

# Function to reset TCP/IP stack
function Reset-TCPIP {
    Write-Host "Resetting TCP/IP stack..." -ForegroundColor Yellow
    netsh int ip reset
}

# Main execution
try {
    Reset-NetworkAdapters
    Reset-IPConfig
    Reset-Winsock
    Clear-DNSCache
    Reset-TCPIP
    
    Write-Host "Network settings have been reset successfully. Please restart your computer for changes to take effect." -ForegroundColor Green
}
catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
}

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")