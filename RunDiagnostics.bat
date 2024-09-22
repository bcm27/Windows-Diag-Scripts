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

:: Set the path to the scripts folder
set "SCRIPT_PATH=%~dp0scripts\Diagnostics-RunAsAdministrator.ps1"

:: Check if the script exists
if not exist "%SCRIPT_PATH%" (
    echo Error: Cannot find the PowerShell script at %SCRIPT_PATH%
    echo Please ensure the script is in the correct location.
    pause
    exit /b 1
)

:: Run the diagnostics script
echo Running Windows Diagnostics script...
powershell -File "%SCRIPT_PATH%"

echo Script execution completed.
pause