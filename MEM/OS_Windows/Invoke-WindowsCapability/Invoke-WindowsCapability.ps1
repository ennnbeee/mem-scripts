$Capability = 'QuickAssist'

Try{
    $WindowsCapability = Get-WindowsCapability -Name *$Capability* -Online
    if($WindowsCapability.State -ne 'Installed'){
        Try{
            Add-WindowsCapability -Online -Name $WindowsCapability.Name
        }
        Catch{
            Break
        }
        
    }

}
Catch{
    Break
}

