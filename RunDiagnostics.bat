@echo off
echo Enabling PowerShell script execution...

:: Check for administrative privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrative privileges confirmed.
) else (
    echo This script requires administrative privileges.
    echo Please run this script as an administrator.
    pause
    exit /b 1
)

:: Enable PowerShell script execution
powershell -Command "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force"
if %errorLevel% == 0 (
    echo PowerShell script execution has been enabled.
) else (
    echo Failed to enable PowerShell script execution.
    pause
    exit /b 1
)

:: Run the diagnostics script
echo Running Windows Diagnostics script...
powershell -File "W11-Diagnostics-Requires-RunAsAdministrator.ps1"

echo Script execution completed.
pause