# Git Repository Manager with Menu
<#
.SYNOPSIS
    A PowerShell script to manage Git repositories: clone, pull, or push changes, now with a menu for user interaction.

.DESCRIPTION
    This script helps manage Git repositories using the Git CLI.
    It provides options to clone a repository, pull the latest changes, or push local changes to a remote repository.

.EXAMPLE
    PS> ./GitRepoManager.ps1
    
    Launches the interactive menu to manage Git repositories.
#>

# Function to display the menu

#------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------
function Show-Menu {
    Write-Host "`nGit Repository Manager Menu" -ForegroundColor Cyan
    Write-Host "1. Clone a repository"
    Write-Host "2. Pull the latest changes"
    Write-Host "3. Push changes to a branch"
    Write-Host "4. Exit"
    Write-Host "`nPlease select an option (1-4): " -NoNewline
    Read-Host
}

# Check if Git is installed
if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) {
    Write-Error "Git CLI is not installed. Please install Git to use this script."
    exit
}

# Menu loop
while ($true) {
    $choice = Show-Menu

    switch ($choice) {
        "1" {
            Write-Host "`n[Clone a Repository]" -ForegroundColor Green
            $repoUrl = Read-Host "Enter the repository URL"
            if ([string]::IsNullOrWhiteSpace($repoUrl)) {
                Write-Error "Repository URL cannot be empty."
                continue
            }
            Write-Host "Cloning repository from URL: $repoUrl" -ForegroundColor Green
            git clone $repoUrl
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Repository cloned successfully!" -ForegroundColor Cyan
            } else {
                Write-Error "Failed to clone the repository."
            }
        }
        "2" {
            Write-Host "`n[Pull the Latest Changes]" -ForegroundColor Green
            $repoPath = Read-Host "Enter the repository path"
            if (-not (Test-Path $repoPath)) {
                Write-Error "The specified repository path does not exist: $repoPath"
                continue
            }
            Write-Host "Pulling latest changes for repository at: $repoPath" -ForegroundColor Green
            Set-Location $repoPath
            git pull
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully pulled latest changes!" -ForegroundColor Cyan
            } else {
                Write-Error "Failed to pull changes."
            }
        }
        "3" {
            Write-Host "`n[Push Changes to a Branch]" -ForegroundColor Green
            $repoPath = Read-Host "Enter the repository path"
            if (-not (Test-Path $repoPath)) {
                Write-Error "The specified repository path does not exist: $repoPath"
                continue
            }
            $branchName = Read-Host "Enter the branch name to push changes to"
            if ([string]::IsNullOrWhiteSpace($branchName)) {
                Write-Error "Branch name cannot be empty."
                continue
            }
            Write-Host "Pushing changes for repository at: $repoPath to branch: $branchName" -ForegroundColor Green
            Set-Location $repoPath
            git push origin $branchName
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Changes pushed successfully!" -ForegroundColor Cyan
            } else {
                Write-Error "Failed to push changes."
            }
        }
        "4" {
            Write-Host "Exiting Git Repository Manager. Goodbye!" -ForegroundColor Yellow
            break
        }
        default {
            Write-Error "Invalid choice. Please select a valid option (1-4)."
        }
    }

    # Reset location to avoid issues
    Set-Location -Path (Get-Location).Path
}
