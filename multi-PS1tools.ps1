# Multi-Tool PowerShell Script
# Objective: Provide a menu-based PowerShell tool integrating multiple administrative tasks.

# Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    exit
}

function Show-Menu {
    Clear-Host
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host "             🌟 Multi-Tool Menu 🌟         " -ForegroundColor Yellow
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[1]  📁 File and Folder Management" -ForegroundColor Green
    Write-Host "[2]  👤 User Account Management (Active Directory)" -ForegroundColor Green
    Write-Host "[3]  🖥️  System Health Check" -ForegroundColor Green
    Write-Host "[4]  💾 Backup Automation" -ForegroundColor Green
    Write-Host "[5]  📜 Log File Analysis" -ForegroundColor Green
    Write-Host "[6]  🕒 Scheduled Task Manager" -ForegroundColor Green
    Write-Host "[7]  ⚙️ Service Monitor and Restart" -ForegroundColor Green
    Write-Host "[8]  📝 Inventory Script" -ForegroundColor Green
    Write-Host "[9]  ☁️ Azure Resource Automation" -ForegroundColor Green
    Write-Host "[10] 📧 Automated Email Reports" -ForegroundColor Green
    Write-Host "[11] 🔄 Git Repository Manager" -ForegroundColor Green
    Write-Host "[12] 📦 Custom Module Creation" -ForegroundColor Green
    Write-Host "[13] 🛠️ Install New Software" -ForegroundColor Green
    Write-Host "[14] 🆑 make your taskbar"   -ForegroundColor Green
    Write-Host "[0]  ❌ Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host " Please enter your choice (0-13):" -ForegroundColor Yellow
}

function FileAndFolderManagement {
    Write-Host "Organizing files and folders..." -ForegroundColor Yellow
    $Directory = Read-Host "Enter the directory to organize"
    if (-not (Test-Path $Directory)) {
        Write-Host "Invalid directory path!" -ForegroundColor Red
        return
    }
    Get-ChildItem -Path $Directory -File | ForEach-Object {
        $Extension = $_.Extension.TrimStart(".")
        $TargetFolder = Join-Path $Directory $Extension
        if (-not (Test-Path $TargetFolder)) { New-Item -ItemType Directory -Path $TargetFolder }
        Move-Item -Path $_.FullName -Destination $TargetFolder -Force
    }
    Write-Host "Files organized by type!" -ForegroundColor Green
}

function UserAccountManagement {
    Write-Host "Managing User Accounts..." -ForegroundColor Yellow
    $CsvFile = Read-Host "Enter the path to the CSV file"
    if (-not (Test-Path $CsvFile)) {
        Write-Host "Invalid file path!" -ForegroundColor Red
        return
    }
    Import-Csv -Path $CsvFile | ForEach-Object {
        if (-not (Get-ADUser -Filter {SamAccountName -eq $_.SamAccountName})) {
            New-ADUser -Name $_.Name -SamAccountName $_.SamAccountName -UserPrincipalName $_.UPN -Path $_.OU -Enabled $true
            Write-Host "Created user: $($_.Name)" -ForegroundColor Green
        } else {
            Write-Host "User already exists: $($_.SamAccountName)" -ForegroundColor Yellow
        }
    }
}

function SystemHealthCheck {
    Write-Host "Performing System Health Check..." -ForegroundColor Yellow
    $CPU = Get-WmiObject Win32_Processor | Select-Object -ExpandProperty LoadPercentage
    $Memory = Get-WmiObject Win32_OperatingSystem | ForEach-Object {
        [math]::Round(($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / $_.TotalVisibleMemorySize * 100, 2)
    }
    $Disk = Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{Name="FreeSpaceGB";Expression={[math]::Round($_.Free / 1GB, 2)}}, @{Name="UsedSpaceGB";Expression={[math]::Round(($_.Used / 1GB), 2)}}
    Write-Host "CPU Usage: $CPU%"
    Write-Host "Memory Usage: $Memory%"
    Write-Host "Disk Usage:"
    $Disk | Format-Table -AutoSize
}

function BackupAutomation {
    Write-Host "Automating Backups..." -ForegroundColor Yellow
    $Source = Read-Host "Enter the source directory"
    $Destination = Read-Host "Enter the backup directory"
    if (-not (Test-Path $Source) -or -not (Test-Path $Destination)) {
        Write-Host "Invalid paths!" -ForegroundColor Red
        return
    }
    $LogFile = Join-Path $Destination "BackupLog.txt"
    Start-Transcript -Path $LogFile -Append
    Copy-Item -Path $Source\* -Destination $Destination -Recurse
    Write-Host "Backup completed!" -ForegroundColor Green
    Stop-Transcript
}

function LogFileAnalysis {
    Write-Host "Analyzing Log Files..." -ForegroundColor Yellow
    $LogFile = Read-Host "Enter the path to the log file"
    $Keyword = Read-Host "Enter the keyword to search for"
    if (-not (Test-Path $LogFile)) {
        Write-Host "Invalid log file path!" -ForegroundColor Red
        return
    }
    $Results = Select-String -Path $LogFile -Pattern $Keyword
    $Results | ForEach-Object {
        Write-Host $_.Line -ForegroundColor Green
    }
}

function ScheduledTaskManager {
    Write-Host "Managing Scheduled Tasks..." -ForegroundColor Yellow
    Write-Host "1. Create Task"
    Write-Host "2. List Tasks"
    Write-Host "3. Remove Task"
    $Choice = Read-Host "Select an option"
    switch ($Choice) {
        "1" {
            $TaskName = Read-Host "Enter the task name"
            $Action = New-ScheduledTaskAction -Execute "notepad.exe"
            $Trigger = New-ScheduledTaskTrigger -AtStartup
            Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName $TaskName
            Write-Host "Task created successfully!" -ForegroundColor Green
        }
        "2" { Get-ScheduledTask | Format-Table }
        "3" {
            $TaskName = Read-Host "Enter the task name"
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host "Task removed successfully!" -ForegroundColor Green
        }
    }
}

function ServiceMonitorAndRestart {
    Write-Host "Monitoring Services..." -ForegroundColor Yellow
    $ServiceName = Read-Host "Enter the name of the service to monitor"
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $Service) {
        Write-Host "Service not found!" -ForegroundColor Red
        return
    }
    if ($Service.Status -ne "Running") {
        Start-Service -Name $ServiceName
        Write-Host "Service restarted: $ServiceName" -ForegroundColor Green
    } else {
        Write-Host "Service is already running: $ServiceName" -ForegroundColor Green
    }
}

function InventoryScript {
    Write-Host "Gathering System Information..." -ForegroundColor Yellow
    $SystemInfo = Get-WmiObject -Class Win32_ComputerSystem
    $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
    Write-Host "System Manufacturer: $($SystemInfo.Manufacturer)"
    Write-Host "Model: $($SystemInfo.Model)"
    Write-Host "OS: $($OSInfo.Caption)"
    Write-Host "Architecture: $($OSInfo.OSArchitecture)"
}

function AzureResourceAutomation {
    Write-Host "Managing Azure Resources..." -ForegroundColor Yellow
    Connect-AzAccount
    Write-Host "Connected to Azure. Please manage resources using Azure commands."
}

function AutomatedEmailReports {
    Write-Host "Sending Email Reports..." -ForegroundColor Yellow
    $SmtpServer = Read-Host "Enter the SMTP server"
    $From = Read-Host "Enter the sender email address"
    $To = Read-Host "Enter the recipient email address"
    $Subject = "Automated Report"
    $Body = "This is an automated system report."
    Send-MailMessage -SmtpServer $SmtpServer -From $From -To $To -Subject $Subject -Body $Body
    Write-Host "Email sent successfully!" -ForegroundColor Green
}

function GitRepositoryManager {

    Write-Host "Opening GitRepo 1 in a new tab..." -ForegroundColor Green
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-File", "C:\Users\sandboxmra\Desktop\GitRepoManager.ps1"

   

  
}

function CustomModuleCreation {
    Write-Host "Creating Custom Module..." -ForegroundColor Yellow
    $ModulePath = Read-Host "Enter the path to save the module"
    $ModuleName = Read-Host "Enter the module name"
    $FullPath = Join-Path $ModulePath "$ModuleName.psm1"
    @"
function Test-Function {
    Write-Host 'This is a test function from the custom module!'
}
Export-ModuleMember -Function Test-Function
"@ | Out-File -FilePath $FullPath
    Write-Host "Module created at $FullPath" -ForegroundColor Green
}

function InstallSoftware {
  
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "          Software Installer        " -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "1. firefox"
    Write-Host "2. pdfQear"
    Write-Host "3. 7-Zip"
    Write-Host "4. Install All"
    Write-Host "0. Exit"
    Write-Host "===================================" -ForegroundColor Cyan

    $selection = Read-Host "Please select an option (1-5)"

    # Define URLs for software downloads
    $firefoxUrl = "https://download.mozilla.org/?product=firefox-stub&os=win64&lang=de"
    $pdfGearUrl = "https://downloadfiles.pdfgear.com/releases/windows/pdfgear_setup_v2.1.11.exe"
    $sevenZipUrl = "https://www.7-zip.org/a/7z2301-x64.exe"

    # Define temporary file paths for downloads
    $tempPath = "$env:Temp"
    $firefoxPath = Join-Path -Path $tempPath -ChildPath "firefox Installer.exe"
    $pdfGearPath = Join-Path -Path $tempPath -ChildPath "pdfgear_setup_v2.1.11.exe"
    $sevenZipPath = Join-Path -Path $tempPath -ChildPath "7zip_installer.exe"

     #---------------------------------------------------------------------------------------------------------------------------------

    switch ($selection) {
        "1" {
                    Write-Host "Downloading and Installing firefox..." -ForegroundColor Green
                    Invoke-WebRequest -Uri $firefoxUrl -OutFile $firefoxPath
                    Start-Process -FilePath $firefoxPath -ArgumentList "/silent", "/install" -NoNewWindow -Wait
                    Write-Host "Firefox installation completed!" -ForegroundColor Green
               }

   #---------------------------------------------------------------------------------------------------------------------------------
         "2" {
            Write-Host "Downloading and Installing PDFGear..." -ForegroundColor Green
            Invoke-WebRequest -Uri $pdfGearUrl -OutFile $pdfGearPath
            Start-Process -FilePath $pdfGearPath -ArgumentList "/S" -NoNewWindow -Wait
            Write-Host "PDFGear installation completed!" -ForegroundColor Green
        }

 #---------------------------------------------------------------------------------------------------------------------------------

        "3" {
            Write-Host "Downloading and Installing 7-Zip..." -ForegroundColor Green
            Invoke-WebRequest -Uri $sevenZipUrl -OutFile $sevenZipPath
            Start-Process -FilePath $sevenZipPath -ArgumentList "/S" -NoNewWindow -Wait
            Write-Host "7-Zip installation completed!" -ForegroundColor Green
        }


   #---------------------------------------------------------------------------------------------------------------------------------
        "4" {
            Write-Host "Downloading and Installing all software..." -ForegroundColor Green

            # Install Google Chrome
            Write-Host "Downloading and Installing Google Chrome..." -ForegroundColor Green
            Invoke-WebRequest -Uri $firefoxUrl -OutFile $firefoxPath
            Start-Process -FilePath $firefoxPath -ArgumentList "/silent", "/install" -NoNewWindow -Wait

            # Install Adobe Reader
            Write-Host "Downloading and Installing Adobe Reader..." -ForegroundColor Green
            Invoke-WebRequest -Uri $pdfGearUrl -OutFile $pdfGearPath
            Start-Process -FilePath $pdfGearPath -ArgumentList "/sAll", "/msi /quiet /norestart" -NoNewWindow -Wait

            # Install 7-Zip
            Write-Host "Downloading and Installing 7-Zip..." -ForegroundColor Green
            Invoke-WebRequest -Uri $sevenZipUrl -OutFile $sevenZipPath
            Start-Process -FilePath $sevenZipPath -ArgumentList "/S" -NoNewWindow -Wait

            Write-Host "All software installed successfully!" -ForegroundColor Green
        }



         #---------------------------------------------------------------------------------------------------------------------------------
        "0" {
            Write-Host "Exiting the installer. Goodbye!" -ForegroundColor Yellow
            return
        }
        default {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            InstallSoftware # Restart the function for valid input
        }

    }
    
        # Run the function
        InstallSoftware
}


# Funktion: taskbarCleaner
function taskbarCleaner {
    Write-Output "Starte Taskleisten-Aufräumprozess..."

    # Widgets deaktivieren
    Write-Output "Deaktiviere Widgets..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0

    # Suchsymbol deaktivieren
    Write-Output "Deaktiviere Suchsymbol..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0

    # Taskleistenausrichtung auf linksbündig setzen
    Write-Output "Setze Taskleistenausrichtung auf linksbündig..."
    $bytes = [byte[]](0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3" -Name "Settings" -Value $bytes

    # Alle Anwendungen von der Taskleiste entfernen (außer Explorer)
    Write-Output "Entferne alle angehefteten Anwendungen von der Taskleiste außer Explorer..."
    $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    Remove-Item "$taskbarPath\*" -Force -ErrorAction SilentlyContinue

    # Explorer wieder anheften
    Write-Output "Explorer an Taskleiste anheften..."
    $explorerPath = "C:\Windows\explorer.exe"
    $shortcutPath = Join-Path -Path $taskbarPath -ChildPath "Explorer.lnk"
    New-Object -ComObject WScript.Shell | ForEach-Object { $_.CreateShortcut($shortcutPath).TargetPath = $explorerPath; $_.Save() }

    # Benachrichtigungen deaktivieren
    Write-Output "Deaktiviere unnötige Benachrichtigungen..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0

    # Explorer neu starten, um Änderungen anzuwenden
    Write-Output "Explorer neu starten, um Änderungen anzuwenden..."
    Stop-Process -Name explorer -Force
    Start-Process explorer

    Write-Output "Taskleisten-Aufräumprozess abgeschlossen!"
}

#




function Exit-Script {
    Write-Host "Exiting... Goodbye!" -ForegroundColor Cyan
    exit
}

# Main Menu Loop
do {
    Show-Menu
    $Selection = Read-Host "Enter your choice"
    switch ($Selection) {
        "1" { FileAndFolderManagement }
        "2" { UserAccountManagement }
        "3" { SystemHealthCheck }
        "4" { BackupAutomation }
        "5" { LogFileAnalysis }
        "6" { ScheduledTaskManager }
        "7" { ServiceMonitorAndRestart }
        "8" { InventoryScript }
        "9" { AzureResourceAutomation }
        "10" { AutomatedEmailReports }
        "11" { GitRepositoryManager }
        "12" { CustomModuleCreation }
        "13" {InstallSoftware}
        "14" {taskbarCleaner}
        "0" { Exit-Script }
        default { Write-Host "Invalid selection, please try again." -ForegroundColor Red }
    }
} while ($true)
