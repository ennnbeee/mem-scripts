<#
    .SYNOPSIS
    This script is used to deploy a baseline configuration for Microsoft Endpoint Manager
    .DESCRIPTION
    Connects to the AAD tenant, creates an App Registation and performs a restore of a pre-definied configuration for Microsoft Endpoint Manager
    .EXAMPLE
    Deploy-FastTrackMEM.ps1 -Windows -Defender -NCSC
    Restores MEM configuration for Windows, Defender Antivirus and NCSC baselines

    Deploy-FastTrackMEM.ps1 -Android -MAM
    Restores MEM configuration for Android Enterprise and Android Mobile Application Management

    .NOTES
    
#>

[CmdletBinding()]
param(
    [Parameter]
    [switch] $Windows,
    [switch] $Android,
    [switch] $iOS,
    [switch] $macOS
)

#Functions
Function Set-MEMGroups{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$CSVPath
	)
    foreach($CSV in $CSVPath){

    $aadgroups = Import-Csv -Path $CSVPath
    foreach($aadgroup in $aadgroups){
        $group = Get-AzureADGroup -SearchString $aadgroup.DisplayName
        if($null -eq $group){
            if($aadgroup.GroupTypes -eq "DynamicMembership"){
                try{
                    New-AzureADMSGroup -DisplayName $aadgroup.DisplayName -MailNickname $aadgroup.DisplayName -Description $aadgroup.Description -MailEnabled $false -SecurityEnabled $true -GroupTypes $aadgroup.GroupTypes -MembershipRule $aadgroup.MembershipRule -membershipRuleProcessingState "On" | out-null
                    Write-Host -ForegroundColor Green "Dynamic Group $($aadgroup.DisplayName) created"       
                }
                catch{
                    Write-Host -ForegroundColor Red "Dynamic Group $($aadgroup.DisplayName) not created" 
                }
            }
            else{
                try{
                    New-AzureADMSGroup -DisplayName $aadgroup.DisplayName -MailNickname $aadgroup.DisplayName -Description $aadgroup.Description -MailEnabled $false -SecurityEnabled $true | out-null
                    Write-Host -ForegroundColor Green "Group $($aadgroup.DisplayName) created"       
                }
                catch{
                    Write-Host -ForegroundColor Red "Group $($aadgroup.DisplayName) Group not created" 
                }    
            }
        }
        else{
            write-host -ForegroundColor Cyan "Group $($aadgroup.DisplayName) already exists"
        }
    }
    }

}
Function Add-MEMModules{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$ModuleName
	)
    Write-Host "Checking for $ModuleName module..." -f Cyan
    $Module = Get-Module -Name $ModuleName -ListAvailable
    if ($null -eq $Module) {
        Try{
            Write-Host "$ModuleName PowerShell module not found, installing module..." -f Yellow
            Write-Host
            Install-Module -Name $ModuleName -Force
            Write-Host "$ModuleName installed" -f Green
            Write-Host
        }
        Catch{
            Write-Host "Unable to install $ModuleName PowerShell module" -f Red
            write-host "Script can't continue..." -f Red
            write-host
            break
        }
    }
    else{
         Try{
            Write-Host "Importing $ModuleName PowerShell module..." -f yellow
            Import-Module -Name $ModuleName
            Write-Host "$ModuleName PowerShell module imported" -f Green
            Write-Host
        }
        Catch{
            Write-Host "Unable to import $ModuleName PowerShell module" -f Red
            write-host "Script can't continue..." -f Red
            break
        }
    }
    

}

#Checking for required PowerShell modules
Write-Host "Starting Intune Deployment for Fast Track" -ForegroundColor yellow -backgroundcolor red
Write-Host "Installing and importing required PowerShell Modules" -ForegroundColor blue
Write-Host
Add-MEMModules -ModuleName AzureADPreview
Add-MEMModules -ModuleName MSGraphFunctions
Add-MEMModules -ModuleName IntuneBackupAndRestore

#Connect to Environment
Write-Host "Connecting to Azure AD and MSGraph" -ForegroundColor blue
Write-Host
Write-Host "When prompted, please enter your username and password or select a signed in account..." -ForegroundColor Cyan
Write-Host
Try{
    Write-Host "Connecting to Azure AD" -f Cyan
    $connection = Connect-AzureAD
    Write-Host "Succesfully connected to Azure AD" -f Green
    Write-Host
}
Catch{
    Write-Host "Unable to connect to Azure AD" -f Red
    write-host "Script can't continue..." -f Red
    write-host
    break
}
Try{
    Write-Host "Connecting to Graph" -f Cyan
    Connect-MSGraph
    Write-Host "Succesfully connected to MS Graph" -f Green
    Write-Host
}
Catch{
    Write-Host "Unable to connect to Graph" -f Red
    write-host "Script can't continue..." -f Red
    write-host
    break
}

#Start Script

$Customer = $connection.TenantDomain
$datetime = Get-Date -format yyyy_MM_dd_HHmmss
$Customerfolder = $Customer + '\' + $datetime
Write-Host "Configuring settings for Intune backup" -ForegroundColor blue
Write-Host


if($PSScriptRoot -notcontains'\'){
    $rootfolder  = $(Write-Host "Please specify the folder where the script is run from" -ForegroundColor Yellow;Read-Host) 
}
else{
    $rootfolder = $PSScriptRoot
}

#Backup of existing environment
$backupfolder = $rootfolder + '\Backup\' + $Customerfolder

Try{
    Write-Host "Starting to backup $Customer Intune configuration to $backupfolder" -f Cyan
    Start-IntuneBackup -Path $backupfolder | Out-Null
    Write-Host "Backup of $Customer Intune configuration to $backupfolder complete" -f Green
    Write-host
}
Catch{
    Write-Host "Unable to backup Intune configuration" -f Red
    write-host "Script can't continue..." -f Red
    write-host
    exit
}


#Restore of configuration
Write-Host "Configuring settings for Intune Restore" -ForegroundColor blue
Write-Host
Write-Host "Added Default group configuration to restore job" -f Cyan
Write-Host
$restorefolders = @()
$groups = @()
$groups += $rootfolder + '\Restore\Groups\Groups.csv'
$groups += $rootfolder + '\Restore\Groups\Groups_Test.csv'


if($Windows){
    $groups += $rootfolder + '\Restore\Groups\Windows.csv'
    $restorefolders += $rootfolder + '\Restore\Windows\'
    Write-Host "Added Windows configuration and groups to restore job" -f Cyan
    Write-Host
}
if($Android){
    $groups += $rootfolder + '\Restore\Groups\Android.csv'
    $restorefolders += $rootfolder + '\Restore\Android\'
    Write-Host "Added Android configuration to restore job" -f Cyan
    Write-Host
}
if($iOS){
    $groups += $rootfolder + '\Restore\Groups\iOS.csv'
    $restorefolders += $rootfolder + '\Restore\iOS\'
    Write-Host "Added iOS configuration to restore job" -f Cyan
    Write-Host
}
if($macOS){
    $groups += $rootfolder + '\Restore\Groups\macOS.csv'
    $restorefolders += $rootfolder + '\Restore\macOS\'
    Write-Host "Added macOS configuration to restore job" -f Cyan
    Write-Host
}
Write-Host "Starting Intune restore job..." -f Blue
Write-Host
Write-Host "Creating Azure AD groups..." -f Cyan
Write-Host
Set-MEMGroups -CSVPath $groups

Write-Host "Restoring templates to $customer Intune environment" -f Cyan
Write-Host
Try{
    Write-Host "Starting to restore configuration to $Customer Intune environment" -f Cyan
    Foreach($restorefolder in $restorefolders){
        Write-Host "Starting Intune restore job with JSON files from $restorefolder..." -f Yellow
        Write-Host
        Start-IntuneRestoreConfig -Path $restorefolder
        Write-Host "Intune restore job $restorefolder complete." -f green
        Write-Host
    }
}
Catch{
    Write-Host "Unable to restore Intune configuration" -f Red
    write-host "Script can't continue..." -f Red
    write-host
    break
}

