function Set-WUfBNotifications {
 
    [cmdletbinding(SupportsShouldProcess=$true)]
    param ()
    $ErrorActionPreference = 'SilentlyContinue'

    $W10Version = ([System.Environment]::OSVersion.Version).Build

    if($W10Version -ge '17763'){
        New-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name RestartNotificationsAllowed2 -Value 1 -PropertyType DWORD -Force
        Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Value 1 -Force -Name RestartNotificationsAllowed2
    }
    elseif ($W10Version -ge '15063' -and $W10Version -le '17134') {
        New-ItemProperty 'HKLM:' -Name RestartNotificationsAllowed -Value 1 -PropertyType DWORD -Force
        Set-ItemProperty 'HKLM:' -Value 1 -Force -Name RestartNotificationsAllowed
    }
    
}
Set-WUfBNotifications
