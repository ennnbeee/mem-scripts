$Capability = 'QuickAssist'

Try{
    $WindowsCapability = Get-WindowsCapability -Name *$Capability* -Online
    if($WindowsCapability.State -eq 'Installed'){
        Write-Host "Installed"
    }

}
Catch{
    Break
}

