# Multi-Tool PowerShell Script
# Objective: Provide a menu-based PowerShell tool integrating multiple administrative tasks.

# Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    exit
}

function Show-Menu {
    Write-Host "========== Multi-Tool Menu ==========" -ForegroundColor Cyan
    Write-Host "1. File and Folder Management"
    Write-Host "2. User Account Management (Active Directory)"
    Write-Host "3. System Health Check"
    Write-Host "4. Backup Automation"
    Write-Host "5. Log File Analysis"
    Write-Host "6. Scheduled Task Manager"
    Write-Host "7. Service Monitor and Restart"
    Write-Host "8. Inventory Script"
    Write-Host "9. Azure Resource Automation"
    Write-Host "10. Automated Email Reports"
    Write-Host "11. Git Repository Manager"
    Write-Host "12. Custom Module Creation"
    Write-Host "0. Exit"
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
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-File", ".\GitRepoManager.ps1"

   

  
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
        "0" { Exit-Script }
        default { Write-Host "Invalid selection, please try again." -ForegroundColor Red }
    }
} while ($true)
