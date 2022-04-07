# Specify profiles
$wifi1 = 'soasinternal'
$wifi2 = 'eduroam'

function Set-WiFiPriority {
    param ()
    $ErrorActionPreference = 'SilentlyContinue'
    # Gets all profiles
    Try{
        $wifiprofiles=(netsh.exe wlan show profiles) -match '\s{1,}:\s'
    }
    Catch{
        Break
    }

    if(($wifiprofiles -match $wifi1) -and ($wifiprofiles -match $wifi2)){
        # Sets Order
        netsh wlan set profileorder name="soasinternal" interface="Wi-Fi" priority=1
        netsh wlan set profileorder name="eduroam" interface="Wi-Fi" priority=2
        # Sets Autoswitch
        netsh wlan set profileparameter name="soasinternal" autoswitch=No
        netsh wlan set profileparameter name="eduroam" autoswitch=Yes
    }
    else{
        write-host "boo" -ForegroundColor red
    }
}

Set-WiFiPriority