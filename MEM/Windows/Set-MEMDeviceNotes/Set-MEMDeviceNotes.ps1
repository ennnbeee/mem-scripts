Function Get-IntuneDeviceNotes{
    <#
    .SYNOPSIS
    Gets the notes of a device in intune.
    
    .DESCRIPTION
    Gets the notes property on a device in intune using the beta Graph api
    
    .PARAMETER DeviceName
    The name of the device that you want to get the notes field from as it appears in intune.
    
    .EXAMPLE
    Get-IntuneDeviceNotes -DeviceName TestDevice01
    
    .NOTES
    Must connect to the graph api first with Connect-MSGraph.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $DeviceName
    )
    Try {
        $DeviceID = (Get-IntuneManagedDevice -filter "deviceName eq '$DeviceName'" -ErrorAction Stop).id
    }
    Catch {
        Write-Error $_.Exception.Message
        break
    }
    #$deviceId = (Get-IntuneManagedDevice -Filter "deviceName eq 'BeesKnees'").id
    $Resource = "deviceManagement/managedDevices('$deviceId')"
    $properties = 'notes'
    $uri = "https://graph.microsoft.com/beta/$($Resource)?select=$properties"
    Try{
        (Invoke-MSGraphRequest -HttpMethod GET -Url $uri -ErrorAction Stop).notes
    }
    Catch{
        Write-Error $_.Exception.Message
        break
    }
}

Function Set-IntuneDeviceNotes{
    <#
    .SYNOPSIS
    Sets the notes on a device in intune.
    
    .DESCRIPTION
    Sets the notes property on a device in intune using the beta Graph api
    
    .PARAMETER DeviceName
    The name of the device as it appears in intune.
    
    .PARAMETER Notes
    A string of the notes that you would like recorded in the notes field in intune.
    
    .EXAMPLE
    Set-IntuneDeviceNotes -DeviceName TestDevice01 -Notes "This is a note on the stuff and things for this device."
    
    .NOTES
    Must connect to the graph api first with Connect-MSGraph.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String]
        $DeviceName,
        [Parameter(Mandatory=$false)]
        [String]
        $Notes
    )
    Try {
        $DeviceID = (Get-IntuneManagedDevice -filter "deviceName eq '$DeviceName'" -ErrorAction Stop).id
    }
    Catch{
        Write-Error $_.Exception.Message
        break
    }
    If (![string]::IsNullOrEmpty($DeviceID)){
        $Resource = "deviceManagement/managedDevices('$DeviceID')"
        $GraphApiVersion = "Beta"
        $URI = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
        $JSONPayload = @"
{
notes:"$Notes"
}
"@
        Try{
            Write-Verbose "$URI"
            Write-Verbose "$JSONPayload"
            Invoke-MSGraphRequest -HttpMethod PATCH -Url $uri -Content $JSONPayload -Verbose -ErrorAction Stop
        }
        Catch{
            Write-Error $_.Exception.Message
            break
        }
    }
}

Connect-MSGraph

$date = Get-Date -format "dd-MM-yyyy"

$Devices = Import-Csv C:\Source\github\mem-scripts\Set-MEMDeviceNotes\devices.csv
$notes = $date + " Device missing Windows Recovery Environment (WinRE) DO NOT reset, wipe or fresh start."

foreach($Device in $Devices){
    Get-IntuneDeviceNotes -DeviceName $Device.Device
}


foreach($Device in $Devices){
    Set-IntuneDeviceNotes -DeviceName $Device.Device -Notes $Notes
}


