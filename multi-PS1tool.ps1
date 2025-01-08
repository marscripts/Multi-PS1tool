# Multi-Tool PowerShell Script
# Objective: Provide a menu-based PowerShell tool integrating multiple administrative tasks.

# Ensure script runs as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    exit
}

function Show-Menu {

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

#---------------------------------------------------------------------------------------------------------------------------------------------------------

function FileAndFolderManagement {
    Write-Host "File and Folder Management Tool" -ForegroundColor Yellow

    # Prompt for the directory to organize
    $Directory = Read-Host "Enter the directory to organize"
    if (-not (Test-Path $Directory)) {
        Write-Host "Error: Invalid directory path!" -ForegroundColor Red
        return
    }

    # Ask if the user wants a dry run
    $DryRun = Read-Host "Do you want a dry-run first? (Yes/No)"
    $IsDryRun = $DryRun -eq "Yes"

    if ($IsDryRun) {
        Write-Host "Performing a dry-run. No changes will be made." -ForegroundColor Cyan
    } else {
        Write-Host "Organizing files and folders..." -ForegroundColor Yellow
    }

    # Process files in the directory
    try {
        $Files = Get-ChildItem -Path $Directory -File
        if ($Files.Count -eq 0) {
            Write-Host "No files found in the directory." -ForegroundColor Yellow
            return
        }

        $Files | ForEach-Object {
            $Extension = $_.Extension.TrimStart(".")
            if ([string]::IsNullOrWhiteSpace($Extension)) {
                $Extension = "NoExtension"
            }
            $TargetFolder = Join-Path $Directory $Extension

            # Dry-run mode: Display actions without performing them
            if ($IsDryRun) {
                Write-Host "Would move file '$($_.Name)' to folder '$TargetFolder'" -ForegroundColor Gray
            } else {
                # Create the target folder if it doesn't exist
                if (-not (Test-Path $TargetFolder)) {
                    New-Item -ItemType Directory -Path $TargetFolder | Out-Null
                    Write-Host "Created folder: $TargetFolder" -ForegroundColor Green
                }
                # Move the file to the target folder
                Move-Item -Path $_.FullName -Destination $TargetFolder -Force
                Write-Host "Moved file '$($_.Name)' to folder '$TargetFolder'" -ForegroundColor Cyan
            }
        }

        Write-Host "Files organized by type!" -ForegroundColor Green

    } catch {
        Write-Error "An error occurred while organizing files: $_"
    }

    # Process folders (Optional: Organize by folder name if needed)
    $OrganizeFolders = Read-Host "Do you want to organize folders too? (Yes/No)"
    if ($OrganizeFolders -eq "Yes") {
        try {
            $Folders = Get-ChildItem -Path $Directory -Directory
            if ($Folders.Count -eq 0) {
                Write-Host "No subfolders found to organize." -ForegroundColor Yellow
            } else {
                $Folders | ForEach-Object {
                    # Example: Move folders with specific logic if needed
                    $FirstLetter = $_.Name.Substring(0, 1).ToUpper()
                    $TargetFolder = Join-Path $Directory $FirstLetter

                    if ($IsDryRun) {
                        Write-Host "Would move folder '$($_.Name)' to '$TargetFolder'" -ForegroundColor Gray
                    } else {
                        # Create target folder if it doesn't exist
                        if (-not (Test-Path $TargetFolder)) {
                            New-Item -ItemType Directory -Path $TargetFolder | Out-Null
                            Write-Host "Created folder: $TargetFolder" -ForegroundColor Green
                        }
                        # Move the folder
                        Move-Item -Path $_.FullName -Destination $TargetFolder -Force
                        Write-Host "Moved folder '$($_.Name)' to '$TargetFolder'" -ForegroundColor Cyan
                    }
                }
                Write-Host "Folders organized by first letter!" -ForegroundColor Green
            }
        } catch {
            Write-Error "An error occurred while organizing folders: $_"
        }
    }

    Write-Host "File and folder management completed!" -ForegroundColor Yellow
}

#---------------------------------------------------------------------------------------------------------------------------------------------------------

function UserAccountManagement {
    Write-Host "User Account Management Tool" -ForegroundColor Yellow

    # Prüfen, ob das Active Directory-Modul geladen ist
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Host "Active Directory-Modul erfolgreich geladen." -ForegroundColor Green
        } catch {
            Write-Error "Das Active Directory-Modul ist nicht verfügbar. Stellen Sie sicher, dass es installiert ist."
            return
        }
    }

    # Prompt for the CSV file path
    $CsvFile = Read-Host "Enter the path to the CSV file"
    if (-not (Test-Path $CsvFile)) {
        Write-Host "Error: Invalid file path!" -ForegroundColor Red
        return
    }

    # Import and process the CSV file
    try {
        $Users = Import-Csv -Path $CsvFile
        Write-Host "Processing $($Users.Count) user(s) from the CSV file..." -ForegroundColor Cyan
    } catch {
        Write-Error "Failed to import the CSV file: $_"
        return
    }

    # Loop through each user in the CSV
    $Users | ForEach-Object {
        try {
            $SamAccountName = $_.SamAccountName
            $Name = $_.Name
            $UPN = $_.UPN
            $OU = $_.OU

            # Validate required fields
            if ([string]::IsNullOrWhiteSpace($SamAccountName) -or [string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($UPN) -or [string]::IsNullOrWhiteSpace($OU)) {
                Write-Host "Skipping invalid entry. Missing required fields for: $Name ($SamAccountName)" -ForegroundColor Red
                return
            }

            # Check if the user already exists
            $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $SamAccountName} -ErrorAction SilentlyContinue
            if ($ExistingUser) {
                Write-Host "User already exists: $SamAccountName" -ForegroundColor Yellow
            } else {
                # Create a new user
                New-ADUser -Name $Name `
                           -SamAccountName $SamAccountName `
                           -UserPrincipalName $UPN `
                           -Path $OU `
                           -Enabled $true `
                           -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
                Write-Host "Created user: $Name ($SamAccountName)" -ForegroundColor Green
            }
        } catch {
            Write-Error "Error processing user $SamAccountName $_"
        }
    }

    Write-Host "User account management process completed!" -ForegroundColor Yellow
}
#---------------------------------------------------------------------------------------------------------------------------------------------------------

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

#---------------------------------------------------------------------------------------------------------------------------------------------------------

function BackupAutomation {
    Write-Host "Automating Backups..." -ForegroundColor Yellow

    # Prompt for source and destination directories
    $Source = Read-Host "Enter the source directory"
    $Destination = Read-Host "Enter the backup directory"

    # Validate paths
    if (-not (Test-Path $Source)) {
        Write-Host "Error: Invalid source directory!" -ForegroundColor Red
        return
    }
    if (-not (Test-Path $Destination)) {
        try {
            Write-Host "Destination directory does not exist. Creating it..." -ForegroundColor Yellow
            New-Item -ItemType Directory -Path $Destination | Out-Null
        } catch {
            Write-Error "Failed to create destination directory: $_"
            return
        }
    }

    # Create a log file in the destination directory
    $LogFile = Join-Path $Destination "BackupLog.txt"
    try {
        Start-Transcript -Path $LogFile -Append
    } catch {
        Write-Error "Failed to start transcript: $_"
        return
    }

    # Exclude certain files or folders (optional)
    $ExcludePatterns = @(".tmp", ".bak", "Thumbs.db")  # Add more patterns if needed
    $ExcludedItems = @()

    # Perform the backup with progress tracking
    Write-Host "Starting backup process..." -ForegroundColor Cyan
    try {
        Get-ChildItem -Path $Source -Recurse | ForEach-Object {
            $RelativePath = $_.FullName.Substring($Source.Length).TrimStart("\")
            $TargetPath = Join-Path $Destination $RelativePath

            # Check if the item matches any exclude pattern
            if ($ExcludePatterns -contains $_.Extension) {
                Write-Host "Excluding: $($_.FullName)" -ForegroundColor Yellow
                $ExcludedItems += $_.FullName
                return
            }

            if ($_.PSIsContainer) {
                # Create directory if it doesn't exist
                if (-not (Test-Path $TargetPath)) {
                    New-Item -ItemType Directory -Path $TargetPath | Out-Null
                    Write-Host "Created directory: $TargetPath" -ForegroundColor Green
                }
            } else {
                # Copy file
                Copy-Item -Path $_.FullName -Destination $TargetPath -Force
                Write-Host "Copied: $($_.FullName) -> $TargetPath" -ForegroundColor Cyan
            }
        }
        Write-Host "Backup completed successfully!" -ForegroundColor Green
    } catch {
        Write-Error "An error occurred during the backup process: $_"
    } finally {
        Stop-Transcript
    }

    # Log excluded items
    if ($ExcludedItems.Count -gt 0) {
        Write-Host "Excluded items:" -ForegroundColor Yellow
        $ExcludedItems | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
    }
}

#---------------------------------------------------------------------------------------------------------------------------------------------------------

function LogFileAnalysis {
    Write-Host "Log File Analysis Tool" -ForegroundColor Yellow

    # Get log file path
    $LogFile = Read-Host "Enter the path to the log file"
    if (-not (Test-Path $LogFile)) {
        Write-Host "Error: Invalid log file path!" -ForegroundColor Red
        return
    }

    # Get keyword to search for
    $Keyword = Read-Host "Enter the keyword to search for"
    if ([string]::IsNullOrWhiteSpace($Keyword)) {
        Write-Host "Error: Keyword cannot be empty!" -ForegroundColor Red
        return
    }

    Write-Host "Searching for keyword '$Keyword' in file '$LogFile'..." -ForegroundColor Cyan

    # Perform search
    try {
        $Results = Select-String -Path $LogFile -Pattern $Keyword
        if ($Results) {
            # Display results
            Write-Host "Found $($Results.Count) matching lines:" -ForegroundColor Green
            $Results | ForEach-Object {
                Write-Host "Line $($_.LineNumber): $($_.Line)" -ForegroundColor Yellow
            }

            # Additional options for results
            Write-Host "What would you like to do with the results?" -ForegroundColor Cyan
            Write-Host "1. Export to file"
            Write-Host "2. View full lines with context"
            Write-Host "3. Exit"
            $Choice = Read-Host "Select an option (1-3)"

            switch ($Choice) {
                "1" {
                    $ExportPath = Read-Host "Enter the export file path"
                    try {
                        $Results | Out-File -FilePath $ExportPath
                        Write-Host "Results exported to $ExportPath" -ForegroundColor Green
                    } catch {
                        Write-Error "Error exporting results: $_"
                    }
                }
                "2" {
                    $ContextLines = Read-Host "Enter the number of context lines to include (default: 2)"
                    if (-not [int]::TryParse($ContextLines, [ref]$null)) {
                        $ContextLines = 2
                    }
                    $ContextResults = Select-String -Path $LogFile -Pattern $Keyword -Context $ContextLines
                    Write-Host "Displaying results with context:" -ForegroundColor Yellow
                    $ContextResults | ForEach-Object {
                        Write-Host "Match found on line $($_.LineNumber): $($_.Line.Trim())" -ForegroundColor Cyan
                        if ($_.Context.PreContext) {
                            Write-Host "Pre-Context:" -ForegroundColor Gray
                            $_.Context.PreContext | ForEach-Object { Write-Host "  $_" }
                        }
                        if ($_.Context.PostContext) {
                            Write-Host "Post-Context:" -ForegroundColor Gray
                            $_.Context.PostContext | ForEach-Object { Write-Host "  $_" }
                        }
                        Write-Host "----"
                    }
                }
                "3" {
                    Write-Host "Exiting the tool." -ForegroundColor Yellow
                }
                default {
                    Write-Host "Invalid option. Exiting." -ForegroundColor Red
                }
            }
        } else {
            Write-Host "No matches found for '$Keyword' in '$LogFile'." -ForegroundColor Red
        }
    } catch {
        Write-Error "Error analyzing log file: $_"
    }
}

#---------------------------------------------------------------------------------------------------------------------------------------------------------

function ScheduledTaskManager {
    Write-Host "Scheduled Task Manager" -ForegroundColor Yellow
    Write-Host "1. Create a Task"
    Write-Host "2. List All Tasks"
    Write-Host "3. View Task Details"
    Write-Host "4. Remove a Task"
    Write-Host "5. Exit"
    
    $Choice = Read-Host "Select an option (1-5)"
    
    switch ($Choice) {
        "1" {
            try {
                $TaskName = Read-Host "Enter the task name"
                $ProgramPath = Read-Host "Enter the full path of the program to execute (e.g., C:\Windows\System32\notepad.exe)"
                $TriggerType = Read-Host "Enter the trigger type (Startup, Daily, or OneTime)"
                $Action = New-ScheduledTaskAction -Execute $ProgramPath
                
                # Configure the trigger based on user input
                switch ($TriggerType.ToLower()) {
                    "startup" { $Trigger = New-ScheduledTaskTrigger -AtStartup }
                    "daily" {
                        $StartTime = Read-Host "Enter the start time (HH:mm)"
                        $Trigger = New-ScheduledTaskTrigger -Daily -At $StartTime
                    }
                    "onetime" {
                        $StartTime = Read-Host "Enter the start time (yyyy-MM-ddTHH:mm)"
                        $Trigger = New-ScheduledTaskTrigger -Once -At $StartTime
                    }
                    default {
                        Write-Host "Invalid trigger type. Task creation aborted." -ForegroundColor Red
                        return
                    }
                }
                
                Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName $TaskName
                Write-Host "Task '$TaskName' created successfully!" -ForegroundColor Green
            } catch {
                Write-Error "Error creating the task: $_"
            }
        }
        "2" {
            try {
                Get-ScheduledTask | Format-Table TaskName, State, Description -AutoSize
            } catch {
                Write-Error "Error listing tasks: $_"
            }
        }
        "3" {
            try {
                $TaskName = Read-Host "Enter the name of the task to view details"
                $Task = Get-ScheduledTask -TaskName $TaskName
                $Task | Format-List
            } catch {
                Write-Error "Error retrieving task details: $_"
            }
        }
        "4" {
            try {
                $TaskName = Read-Host "Enter the name of the task to remove"
                if ([string]::IsNullOrWhiteSpace($TaskName)) {
                    Write-Host "Task name cannot be empty. Operation aborted." -ForegroundColor Red
                    return
                }
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
                Write-Host "Task '$TaskName' removed successfully!" -ForegroundColor Green
            } catch {
                Write-Error "Error removing the task: $_"
            }
        }
        "5" {
            Write-Host "Exiting Scheduled Task Manager." -ForegroundColor Yellow
            return
        }
        default {
            Write-Host "Invalid option. Please select a valid option (1-5)." -ForegroundColor Red
            ScheduledTaskManager
        }
    }
}

#---------------------------------------------------------------------------------------------------------------------------------------------------------


function ServiceMonitorAndRestart {
    Write-Host "Service Monitoring and Restart Tool" -ForegroundColor Yellow

    # Prompt for the service name
    $ServiceName = Read-Host "Enter the name of the service to monitor"

    # Check if the service exists
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $Service) {
        Write-Host "Error: Service not found!" -ForegroundColor Red
        return
    }

    # Prompt for monitoring interval
    $Interval = Read-Host "Enter the monitoring interval in seconds (default: 30)"
    if (-not [int]::TryParse($Interval, [ref]$null)) {
        $Interval = 30
    }

    # Continuous monitoring loop
    Write-Host "Monitoring service '$ServiceName' every $Interval seconds. Press Ctrl+C to stop." -ForegroundColor Cyan
    try {
        while ($true) {
            $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $Service) {
                Write-Host "Service '$ServiceName' no longer exists!" -ForegroundColor Red
                break
            }

            if ($Service.Status -ne "Running") {
                Write-Host "Service '$ServiceName' is not running. Attempting to restart..." -ForegroundColor Yellow
                try {
                    Start-Service -Name $ServiceName
                    Write-Host "Service restarted successfully: $ServiceName" -ForegroundColor Green
                } catch {
                    Write-Error "Failed to restart service '$ServiceName': $_"
                }
            } else {
                Write-Host "Service is running: $ServiceName" -ForegroundColor Green
            }

            # Wait for the specified interval
            Start-Sleep -Seconds $Interval
        }
    } catch {
        Write-Error "An error occurred during service monitoring: $_"
    }
}

#---------------------------------------------------------------------------------------------------------------------------------------------------------


function InventoryScript {
    Write-Output "`n=== Inventory Script ==="
    
    # Get Operating System details
    Write-Output "`n=== Operating System Information ==="
    $osInfo = Get-ComputerInfo | Select-Object -Property WindowsVersion, WindowsBuildLabEx, OsArchitecture, CsName, WindowsRegisteredOrganization, WindowsRegisteredOwner
    $osInfo | Format-List

    # Get Hardware Information
    Write-Output "`n=== Hardware Information ==="
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $processor = Get-WmiObject -Class Win32_Processor

    Write-Output "Manufacturer: $($computerSystem.Manufacturer)"
    Write-Output "Model: $($computerSystem.Model)"
    Write-Output "Total Physical Memory (GB): $([Math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2))"
    Write-Output "Processor: $($processor.Name)"
    Write-Output "Processor Cores: $($processor.NumberOfCores)"
    Write-Output "Processor Logical Processors: $($processor.NumberOfLogicalProcessors)"

    # Get list of installed applications
    Write-Output "`n=== Installed Applications ==="
    $apps = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `
        , "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
        , "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `
        | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName

    if ($apps) {
        $apps | Where-Object { $_.DisplayName -ne $null } | Format-Table -AutoSize
    } else {
        Write-Output "No applications found."
    }

    Write-Output "`nReport Completed."
}


#---------------------------------------------------------------------------------------------------------------------------------------------------------




function AzureResourceAutomation {
    Write-Host "Azure Resource Automation Tool" -ForegroundColor Yellow

    # Try connecting to Azure
    try {
        Write-Host "Connecting to Azure..." -ForegroundColor Cyan
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Successfully connected to Azure!" -ForegroundColor Green
    } catch {
        Write-Error "Failed to connect to Azure. Please check your credentials and network connection."
        return
    }

    # Display menu for resource management
    while ($true) {
        Write-Host "`nSelect an option:" -ForegroundColor Yellow
        Write-Host "1. List Resources"
        Write-Host "2. Create a Resource Group"
        Write-Host "3. Delete a Resource Group"
        Write-Host "4. Exit"

        $Choice = Read-Host "Enter your choice (1-4)"

        switch ($Choice) {
            "1" {
                try {
                    Write-Host "Fetching resources..." -ForegroundColor Cyan
                    $Resources = Get-AzResource
                    if ($Resources.Count -eq 0) {
                        Write-Host "No resources found in the current subscription." -ForegroundColor Yellow
                    } else {
                        $Resources | Format-Table Name, ResourceType, ResourceGroup, Location -AutoSize
                    }
                } catch {
                    Write-Error "Failed to retrieve resources. Ensure you have access to a subscription."
                }
            }
            "2" {
                try {
                    $ResourceGroupName = Read-Host "Enter the name of the new resource group"
                    $Location = Read-Host "Enter the location (e.g., eastus, westus)"
                    Write-Host "Creating resource group '$ResourceGroupName' in location '$Location'..." -ForegroundColor Cyan
                    New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
                    Write-Host "Resource group '$ResourceGroupName' created successfully!" -ForegroundColor Green
                } catch {
                    Write-Error "Failed to create the resource group. Ensure the location is valid."
                }
            }
            "3" {
                try {
                    $ResourceGroupName = Read-Host "Enter the name of the resource group to delete"
                    $Confirm = Read-Host "Are you sure you want to delete resource group '$ResourceGroupName'? This action cannot be undone! (Yes/No)"
                    if ($Confirm -eq "Yes") {
                        Write-Host "Deleting resource group '$ResourceGroupName'..." -ForegroundColor Cyan
                        Remove-AzResourceGroup -Name $ResourceGroupName -Force -ErrorAction Stop
                        Write-Host "Resource group '$ResourceGroupName' deleted successfully!" -ForegroundColor Green
                    } else {
                        Write-Host "Deletion cancelled." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Error "Failed to delete the resource group. Ensure the name is correct and you have permissions."
                }
            }
            "4" {
                Write-Host "Exiting Azure Resource Automation Tool. Goodbye!" -ForegroundColor Yellow
                break
            }
            default {
                Write-Host "Invalid choice. Please enter a number between 1 and 4." -ForegroundColor Red
            }
        }
    }
}


#---------------------------------------------------------------------------------------------------------------------------------------------------------

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

#---------------------------------------------------------------------------------------------------------------------------------------------------------

function GitRepositoryManager {
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "         Git Repository Manager     " -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan

    # Check if Git is installed
    if (!(Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "Git is not installed on this system." -ForegroundColor Yellow
        $InstallGit = Read-Host "Do you want to install Git? (Yes/No)"
        if ($InstallGit -eq "Yes") {
            if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
                Write-Host "Chocolatey is not installed. Installing Chocolatey..." -ForegroundColor Yellow
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Chocolatey installation completed successfully!" -ForegroundColor Green
                } else {
                    Write-Host "Failed to install Chocolatey. Exiting." -ForegroundColor Red
                    return
                }
            }

            Write-Host "Installing Git via Chocolatey..." -ForegroundColor Cyan
            choco install git -y
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Git installed successfully!" -ForegroundColor Green
                $env:PATH += ";C:\Program Files\Git\bin"
            } else {
                Write-Host "Failed to install Git. Exiting." -ForegroundColor Red
                return
            }
        } else {
            Write-Host "Git is required for this tool to work. Exiting." -ForegroundColor Red
            return
        }
    }

    # Verify Git availability
    if (!(Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "Git is still not recognized. Ensure it is added to PATH and try again." -ForegroundColor Red
        return
    }

    # Main menu
    while ($true) {
        Write-Host "`nSelect an option:" -ForegroundColor Yellow
        Write-Host "1. Clone a repository"
        Write-Host "2. Pull changes from a repository"
        Write-Host "3. Push updates to a repository"
        Write-Host "0. Exit"
        Write-Host "===================================" -ForegroundColor Cyan

        $Choice = Read-Host "Enter your choice (1-4)"

        switch ($Choice) {
            "1" {
                # Clone a repository
                $RepoURL = Read-Host "Enter the repository URL to clone"
                $Destination = Read-Host "Enter the destination directory (leave blank for current directory)"
                if ([string]::IsNullOrWhiteSpace($Destination)) {
                    $Destination = "."
                }

                Write-Host "Cloning repository from '$RepoURL' to '$Destination'..." -ForegroundColor Cyan
                git clone $RepoURL $Destination
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Repository cloned successfully!" -ForegroundColor Green
                } else {
                    Write-Host "Failed to clone repository. Check the URL and try again." -ForegroundColor Red
                }
            }
            "2" {
                # Pull changes
                $RepoPath = Read-Host "Enter the path to the local repository"
                if (-not (Test-Path $RepoPath)) {
                    Write-Host "Invalid path! Please enter a valid repository path." -ForegroundColor Red
                } else {
                    Set-Location -Path $RepoPath
                    Write-Host "Pulling changes from the remote repository..." -ForegroundColor Cyan
                    git pull
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Changes pulled successfully!" -ForegroundColor Green
                    } else {
                        Write-Host "Failed to pull changes. Check the repository status." -ForegroundColor Red
                    }
                    Set-Location -Path (Get-Location).Path
                }
            }
            "3" {
                # Push updates
                $RepoPath = Read-Host "Enter the path to the local repository"
                if (-not (Test-Path $RepoPath)) {
                    Write-Host "Invalid path! Please enter a valid repository path." -ForegroundColor Red
                } else {
                    Set-Location -Path $RepoPath
                    $CommitMessage = Read-Host "Enter a commit message for your changes"
                    Write-Host "Staging changes..." -ForegroundColor Cyan
                    git add .
                    Write-Host "Committing changes with message: '$CommitMessage'..." -ForegroundColor Cyan
                    git commit -m $CommitMessage
                    Write-Host "Pushing updates to the remote repository..." -ForegroundColor Cyan
                    git push
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "Updates pushed successfully!" -ForegroundColor Green
                    } else {
                        Write-Host "Failed to push updates. Check the repository status." -ForegroundColor Red
                    }
                    Set-Location -Path (Get-Location).Path
                }
            }
            "0" {
                # Exit
                Write-Host "Exiting Git Repository Manager. Goodbye!" -ForegroundColor Yellow
                return 
            }
            default {
                Write-Host "Invalid choice. Please enter a valid option." -ForegroundColor Red
            }
        }
    }
    GitRepositoryManager
}

#---------------------------------------------------------------------------------------------------------------------------------------------------------

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


#---------------------------------------------------------------------------------------------------------------------------------------------------------

function InstallSoftware {
    # Function Header
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "          Software Installer        " -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "1. Firefox"
    Write-Host "2. PDFGear"
    Write-Host "3. 7-Zip"
    Write-Host "4. GitHub Desktop"
    Write-Host "5. Visual Studio Code"
    Write-Host "6. VMware Workstation"
    Write-Host "7. VirtualBox"
    Write-Host "00. Install All"
    Write-Host "0. Exit"
    Write-Host "===================================" -ForegroundColor Cyan

    # Get user selection
    $selection = Read-Host "Please select an option (1-7, 00, 0)"

    # Check if Chocolatey is installed
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Chocolatey is not installed. Installing Chocolatey..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Chocolatey installation completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Failed to install Chocolatey. Exiting the installer." -ForegroundColor Red
            return
        }
    }

    # Define a function to install a package via Chocolatey
    function Install-ChocoPackage {
        param (
            [string]$PackageName
        )
        Write-Host "Installing $PackageName..." -ForegroundColor Green
        choco install $PackageName -y
        if ($LASTEXITCODE -eq 0) {
            Write-Host "$PackageName installation completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Failed to install $PackageName. Check for errors." -ForegroundColor Red
        }
    }

    # Map package names to options for extensibility
    $softwarePackages = @{
        "1"  = "firefox"
        "2"  = "pdfgear"
        "3"  = "7zip"
        "4"  = "github-desktop"
        "5"  = "vscode"
        "6"  = "vmwareworkstation"
        "7"  = "virtualbox"
        "00" = @("firefox", "pdfgear", "7zip", "github-desktop", "vscode", "vmwareworkstation", "virtualbox")
    }

    # Process the selection
    switch ($selection) {
        { $_ -in $softwarePackages.Keys } {
            # Install one or multiple packages
            $packages = $softwarePackages[$_]
            if ($packages -is [string]) {
                Install-ChocoPackage -PackageName $packages
            } elseif ($packages -is [array]) {
                foreach ($pkg in $packages) {
                    Install-ChocoPackage -PackageName $pkg
                }
                Write-Host "All selected software installed successfully!" -ForegroundColor Green
            }
        }
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


#---------------------------------------------------------------------------------------------------------------------------------------------------------


function taskbarCleaner {
    Write-Output "Starte Taskleisten-Aufräumprozess..."

    # Widgets deaktivieren
    Write-Output "Deaktiviere Widgets..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0
        Write-Output "Widgets erfolgreich deaktiviert."
    } catch {
        Write-Error "Fehler beim Deaktivieren der Widgets: $_"
    }

    # Suchsymbol deaktivieren
    Write-Output "Deaktiviere Suchsymbol..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 3
        Write-Output "Suchsymbol erfolgreich deaktiviert."
    } catch {
        Write-Error "Fehler beim Deaktivieren des Suchsymbols: $_"
    }

    # Taskleistenausrichtung auf linksbündig setzen
    Write-Output "Setze Taskleistenausrichtung auf linksbündig..."
    $alignmentBytes = [byte[]](
        0x28, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    )
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3" -Name "Settings" -Value $alignmentBytes
        Write-Output "Taskleistenausrichtung erfolgreich geändert."
    } catch {
        Write-Error "Fehler beim Setzen der Taskleistenausrichtung: $_"
    }

    # Entferne alle angehefteten Anwendungen von der Taskleiste außer Explorer
    Write-Output "Entferne alle angehefteten Anwendungen von der Taskleiste außer Explorer..."
    $taskbarPath = Join-Path $env:APPDATA "Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
    if (Test-Path $taskbarPath) {
        try {
            Get-ChildItem -Path $taskbarPath -Force | ForEach-Object {
                if ($_.Name -notlike "*explorer*.lnk") {
                    Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                    Write-Output "Entfernt: $($_.Name)"
                } else {
                    Write-Output "Beibehalten: $($_.Name) (Explorer)"
                }
            }
        } catch {
            Write-Error "Fehler beim Entfernen angehefteter Anwendungen: $_"
        }
    } else {
        Write-Warning "Taskleisten-Verknüpfungen-Ordner nicht gefunden: $taskbarPath"
    }

    # Explorer an Taskleiste anheften
    Write-Output "Explorer an Taskleiste anheften..."
    try {
        $explorerPath = "C:\Windows\explorer.exe"
        $pinnedPath = Join-Path $env:APPDATA "Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        if (!(Test-Path $pinnedPath)) {
            New-Item -Path $pinnedPath -ItemType Directory -Force | Out-Null
        }
        $shortcutPath = Join-Path $pinnedPath "Explorer.lnk"
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $explorerPath
        $shortcut.Save()
        Write-Output "Explorer erfolgreich angeheftet."
    } catch {
        Write-Error "Fehler beim Anheften des Explorers: $_"
    }

    # Deaktiviere unnötige Benachrichtigungen
    Write-Output "Deaktiviere unnötige Benachrichtigungen..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0
        Write-Output "Benachrichtigungen erfolgreich deaktiviert."
    } catch {
        Write-Error "Fehler beim Deaktivieren der Benachrichtigungen: $_"
    }

    # Explorer neu starten, um alle Änderungen anzuwenden
    Write-Output "Starte Explorer neu, um Änderungen anzuwenden..."
    try {
        Stop-Process -Name explorer -Force
        Start-Process explorer
        Write-Output "Taskleisten-Aufräumprozess abgeschlossen!"
    } catch {
        Write-Error "Fehler beim Neustarten des Explorers: $_"
    }
}


#---------------------------------------------------------------------------------------------------------------------------------------------------------


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
}while ($true)
