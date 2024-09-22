# Windows Diagnostics Tool

The Windows Diagnostics Tool is a comprehensive utility designed to help users diagnose and troubleshoot various aspects of their Windows system. This tool combines a user-friendly batch script interface with a powerful PowerShell backend to perform a wide range of diagnostic tests.

## Features

- System Information Check
- Disk Health Analysis
- Windows Update Status
- Running Processes List
- Critical Services Status
- Network Connectivity Test
- System File Integrity Check
- Security Issues Scan
- Virus and Malware Detection
- Performance Metrics Gathering

## Prerequisites

- Windows 10 or later
- PowerShell 5.1 or later
- Administrative privileges

## Installation

1. Download the `RunDiagnostics.bat` and `Diagnostics-RunAsAdministrator.ps1` files.
3. Ensure the `Diagnostics-RunAsAdministrator.ps1` file is in a `scripts` subfolder relative to `RunDiagnostics.bat`.

## Usage

1. Right-click on `RunDiagnostics.bat` and select "Run as administrator".
2. The script will enable PowerShell execution and launch the main diagnostic tool.
3. You will be presented with a menu of diagnostic options:
   - Select individual tests by entering their corresponding numbers (1-10).
   - Choose 'R' to run all tests.
   - Choose 'S' to run all tests except security-related ones.
   - Choose 'Q' to quit.
4. After selecting tests, you can choose to run them immediately or add more tests.
5. The tool will execute the selected tests and provide real-time progress updates.
6. Results will be displayed in the console and saved to a log file on your desktop.

## Troubleshooting

### Execution Policy Error

If you encounter an error message similar to:

```
Windows-Diag-Scripts-dev\scripts\Diagnostics-RunAsAdministrator.ps1 cannot be loaded. The file ..\Windows-Diag-Scripts-dev\scripts\Diagnostics-RunAsAdministrator.ps1 is not digitally signed. You cannot run this script on the current system.
```

This error occurs due to Windows PowerShell's default execution policy, which restricts running unsigned scripts for security reasons. To resolve this:

1. Open PowerShell as Administrator.
2. Run the following command to check your current execution policy:
   ```
   Get-ExecutionPolicy
   ```
3. If it's set to "Restricted", you can change it to allow local scripts by running:
   ```
   Set-ExecutionPolicy unrestricted -Scope CurrentUser
   ```
4. When prompted, type 'Y' and press Enter to confirm the change.

After changing the execution policy, try running the diagnostic tool again.

**Note:** Changing the execution policy can have security implications. Only run scripts from sources you trust, and consider reverting the policy after running the diagnostic tool if you're concerned about security.

To set it back run:
   ```
   Set-ExecutionPolicy restricted -Scope CurrentUser
   ```
### Other Issues

- If you encounter any "Access Denied" errors, make sure you're running the batch file as an administrator.
- Ensure that both the `RunDiagnostics.bat` and `Diagnostics-RunAsAdministrator.ps1` files are in the correct locations as described in the Installation section.

If you continue to experience issues, please open an issue on the GitHub repository with details about the error and your system configuration.

## Log Files

- Log files are automatically created on your desktop with the naming convention `WindowsDiagnostics_YYYY-MM-DD_HH-MM-SS.log`.
- These logs contain detailed information about the tests performed and their results.

## Security Note

This tool requires administrative privileges to perform comprehensive system diagnostics. Always ensure you trust the source of the scripts before running them with elevated permissions.

## Troubleshooting

- If you encounter any "Access Denied" errors, make sure you're running the batch file as an administrator.
- If PowerShell script execution fails, you may need to adjust your execution policy manually:
  1. Open PowerShell as administrator
  2. Run `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

## Contributing

Contributions to improve the Windows Diagnostics Tool are welcome. Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
