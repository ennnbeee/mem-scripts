# Set the Group Tag
$GroupTag = "AAD-ASSIGNED-STAFF"

Connect-MSGraph
Update-MSGraphEnvironment -SchemaVersion "Beta" -Quiet
Connect-MSGraph -Quiet
Import-Module azuread
Connect-AzureAd
Import-Module -Name WindowsAutoPilotIntune

# Get all autopilot devices (even if more than 1000)
$autopilotDevices = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/windowsAutopilotDeviceIdentities" | Get-MSGraphAllPages

# Display gridview to show devices
#$selectedAutopilotDevices =  $autopilotDevices | Out-GridView -OutputMode Multiple -Title "Select Windows Autopilot entities to update"

# Arrays to play with
$aaddeviceids = New-Object -TypeName System.Collections.ArrayList
$apdeviceids = New-Object -TypeName System.Collections.ArrayList
$apdeviceserials = New-Object -TypeName System.Collections.ArrayList
# Import CSV of devices to update

$apDevicesCSV = Import-Csv -Path "C:\Users\Nick-Benton\Downloads\wapdevices.csv"
foreach($apDeviceCSV in $apDevicesCSV){
    #$aaddevice = Get-AzureADDevice -Filter "DisplayName eq '$($apDeviceCSV.displayName)'"
    #$aaddeviceids.AddRange(@(
    #    $aaddevice.DeviceID
    #))
    if($apDeviceCSV.'Group tag' -eq ""){
        
        $apdeviceserials.AddRange(@(
        $apDeviceCSV.'Serial number'
        ))
    }

}

foreach($autopilotDevice in $autopilotDevices){
    if($autopilotDevice.groupTag -eq ""){
        foreach($apdeviceserial in $apdeviceserials){
            if($apdeviceserial -eq $autopilotDevice.serialNumber){
                Set-AutopilotDevice -id $autopilotDevice.id -groupTag $groupTag
                write-host -ForegroundColor Green "Group tag $groupTag assigned to $apdeviceserial"
            }

        }
    }
    else{
        write-host -ForegroundColor Cyan "Group tag $($autopilotDevice.groupTag) already assigned to $($autopilotDevice.serialNumber)"
    }

}    


$selectedAutopilotDevices | ForEach-Object {

    $autopilotDevice = $PSItem

    # Change names according to your environment
    $autopilotDevice.groupTag = $GroupTag
    #$autopilotDevice.orderIdentifier = "ORDER1234" | updating orderidentifier is currently not supported

    $requestBody=
@"
    {
        groupTag: `"$($autopilotDevice.groupTag)`",
    }
"@
    Write-Output "Updating entity: $($autopilotDevice.id) | groupTag: $($autopilotDevice.groupTag) | orderIdentifier: $($autopilotDevice.orderIdentifier)"
    Invoke-MSGraphRequest -HttpMethod POST -Content $requestBody -Url "deviceManagement/windowsAutopilotDeviceIdentities/$($autopilotDevice.id)/UpdateDeviceProperties" 
}

# Invoke an autopilot service sync
Invoke-MSGraphRequest -HttpMethod POST -Url "deviceManagement/windowsAutopilotSettings/sync"