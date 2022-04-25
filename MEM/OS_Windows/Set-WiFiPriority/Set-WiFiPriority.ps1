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
        Try{
            netsh wlan set profileorder name=$wifi1 interface="Wi-Fi" priority=1
            netsh wlan set profileorder name=$wifi2 interface="Wi-Fi" priority=2
        }
        Catch{
            Break
        }

    }
    else{
        Break
    }
}

Set-WiFiPriority