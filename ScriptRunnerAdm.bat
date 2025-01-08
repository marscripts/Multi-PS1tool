@echo off
:: Check for administrative privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    :: Relaunch the batch file with administrator privileges
    echo Requesting administrative privileges...
    powershell.exe -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Path to the PowerShell script
set PowerShellScript=".\multi-PS1tool.ps1"

:: Check if the PowerShell script exists
if not exist %PowerShellScript% (
    echo PowerShell script not found at: %PowerShellScript%
    echo Please verify the path and try again.
    pause
    exit /b
)

:: Run the PowerShell script as administrator
echo Running PowerShell script as administrator...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File %PowerShellScript%
pause
