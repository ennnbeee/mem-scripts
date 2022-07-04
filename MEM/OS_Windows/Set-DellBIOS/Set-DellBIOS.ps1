$NewPassword = "NewSecurePassword"
$OldPassword = "OldStupidPassword"
$DetectionRegPath = "HKLM:\SOFTWARE\IntuneHelper\DellBIOSProvider"
$DetectionRegNamePassword = "PasswordSet"
$ScriptPath = (Get-Location).Path
$CSV = "$ScriptPath\BIOS_Settings.csv"																																			
$CSVContent = Import-CSV $CSV  -Delimiter ","

Start-Transcript -Path "$env:TEMP\Set-DellBIOS.log" | Out-Null

if (!(Test-Path -Path $DetectionRegPath)) {
    New-Item -Path $DetectionRegPath -Force | Out-Null
}

if (Test-Path -Path "$env:ProgramFiles\WindowsPowerShell\Modules\DellBIOSProvider") {
    Write-Output "DellBIOSProvider folder already exists @ $env:ProgramFiles\WindowsPowerShell\Modules\DellBIOSProvider."
    Write-Output "Deleting the folder..."
    Remove-Item -Path "$env:ProgramFiles\WindowsPowerShell\Modules\DellBIOSProvider" -Recurse -Force
}
 
Write-Output "Copying DellBIOSProvider module to: $env:ProgramFiles\WindowsPowerShell\Modules\DellBIOSProvider"
Copy-Item -Path "$ScriptPath\DellBIOSProvider\" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\DellBIOSProvider" -Recurse -Force

try {
    Import-Module "DellBIOSProvider" -Force -Verbose -ErrorAction Stop
    Write-Output "Importing the Dell BIOS Provider module"
}
catch {
    Write-Output "Error importing module: $_"
    exit 1
}

Get-DellBiosSettings

$IsAdminPassSet = (Get-Item -Path DellSmbios:\Security\IsAdminPasswordSet).CurrentValue
 
if ($IsAdminPassSet -eq $false) {
    Write-Output "Admin password is not set at this moment, will try to set it."
    Set-Item -Path DellSmbios:\Security\AdminPassword "$NewPassword"
    if ( (Get-Item -Path DellSmbios:\Security\IsAdminPasswordSet).CurrentValue -eq $true ) {
        Write-Output "Admin password has now been set."
        New-ItemProperty -Path "$DetectionRegPath" -Name "$DetectionRegNamePassword" -Value 1 | Out-Null
    }
}
else {
    Write-Output "Admin password is already set"
    if ($null -eq $OldPassword) {
        Write-Output "`$OldPassword variable has not been specified, will not attempt to change admin password"
 
    }
    else {
        Write-Output "`$OldPassword variable has been specified, will try to change the admin password"
        Set-Item -Path DellSmbios:\Security\AdminPassword "$NewPassword" -Password "$OldPassword"
        New-ItemProperty -Path "$DetectionRegPath" -Name "$DetectionRegName" -Value 1 | Out-Null
    }
}
 
				

$DiskPart = (Get-Disk -number 0).PartitionStyle

$BIOSSettings = get-childitem -path DellSmbios:\
foreach ($BIOSSetting in $BIOSSettings) {
    get-childitem -path @("DellSmbios:\" + $_.Category)  | select-object attribute, currentvalue, possiblevalues, PSChildName 
}   

ForEach ($New_Setting in $Get_CSV_Content) { 
    $Setting_To_Set = $New_Setting.Setting 
    $Setting_NewValue_To_Set = $New_Setting.Value 
		
    Add-Content $Log_File  "" 
    Write_Log -Message_Type "INFO" -Message "Change to do: $Setting_To_Set > $Setting_NewValue_To_Set"  
		
    ForEach ($Current_Setting in $Dell_BIOS | Where { $_.attribute -eq $Setting_To_Set }) { 
        $Attribute = $Current_Setting.attribute
        $Setting_Cat = $Current_Setting.PSChildName
        $Setting_Current_Value = $Current_Setting.CurrentValue

        If (($IsPasswordSet -eq $true)) {   
            $Password_To_Use = $MyPassword
            Try {
                & Set-Item -Path Dellsmbios:\$Setting_Cat\$Attribute -Value $Setting_NewValue_To_Set -Password $Password_To_Use
                Write_Log -Message_Type "SUCCESS" -Message "New value for $Attribute is $Setting_Current_Value"  						
            }
            Catch {
                Write_Log -Message_Type "ERROR" -Message "Can not change setting $Attribute (Return code $Change_Return_Code)"  																		
            }
        }
        Else {
            Try {
                & Set-Item -Path Dellsmbios:\$Setting_Cat\$Attribute -Value $Setting_NewValue_To_Set  
                Write_Log -Message_Type "SUCCESS" -Message "New value for $Attribute is $Setting_Current_Value"  						
            }
            Catch {
                Write_Log -Message_Type "ERROR" -Message "Can not change setting $Attribute (Return code $Change_Return_Code)"  																		
            }						
        }        
    }  
}  

Stop-Transcript