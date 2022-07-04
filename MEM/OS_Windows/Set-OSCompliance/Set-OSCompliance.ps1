function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    if ($userUpn.Host -like "*onmicrosoft.com*") {
        $tenant = Read-Host -Prompt "Please specify your Tenant name i.e. company.com"
        Write-Host
    }
    else {
        $tenant = $userUpn.Host
    }
    
    
    Write-Host "Checking for AzureAD module..."
    
    $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
    if ($null -eq $AadModule) {
    
        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
    }
    
    if ($null -eq $AadModule) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
    if ($AadModule.count -gt 1) {
    
        $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
    
        $aadModule = $AadModule | Where-Object { $_.version -eq $Latest_Version.version }
    
        # Checking if there are multiple versions of the same module found
    
        if ($AadModule.count -gt 1) {
    
            $aadModule = $AadModule | Select-Object -Unique
    
        }
    
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
            
    
    }
    
    else {
    
        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
    }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
    try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
             
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
    
        # If the accesstoken is valid then create the authentication header
    
        if ($authResult.AccessToken) {
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.AccessToken
                'ExpiresOn'     = $authResult.ExpiresOn
            }
    
            return $authHeader
    
        }
    
        else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
        }
    
    }
    
    catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
    }
    
}

Function Test-JSON() {

    <#
    .SYNOPSIS
    This function is used to test if the JSON passed to a REST Post request is valid
    .DESCRIPTION
    The function tests if the JSON passed to the REST Post is valid
    .EXAMPLE
    Test-JSON -JSON $JSON
    Test if the JSON is valid before calling the Graph REST interface
    .NOTES
    NAME: Test-JSON
    #>
    
    param (
    
        $JSON
    
    )
    
    try {
    
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $validJson = $true
    
    }
    
    catch {
    
        $validJson = $false
        $_.Exception
    
    }
    
    if (!$validJson) {
        
        Write-Host "Provided JSON isn't in valid JSON format" -f Red
        break
    
    }
    
}

Function Get-DeviceCompliancePolicy() {

    <#
    .SYNOPSIS
    This function is used to get device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies
    .EXAMPLE
    Get-DeviceCompliancePolicy
    Returns any device compliance policies configured in Intune
    .EXAMPLE
    Get-DeviceCompliancePolicy -Android
    Returns any device compliance policies for Android configured in Intune
    .EXAMPLE
    Get-DeviceCompliancePolicy -iOS
    Returns any device compliance policies for iOS configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    
  
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}

Function Update-DeviceCompliancePolicy() {

    <#
    .SYNOPSIS
    This function is used to update device compliance policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and updates device compliance policies
    .EXAMPLE
    Update-DeviceCompliancePolicy -id -JSON
    Updates a device compliance policies configured in Intune
    .NOTES
    NAME: Update-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    param
    (
        $Id,
        $JSON
    )
  
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies/$id"
    
    try {

        if (!$Id) {

            write-host "No Compliance Policy Id specified, specify a valid Compliance Policy Id" -f Red
            break
    
        }
    
        if ($JSON -eq "" -or $null -eq $JSON) {

            write-host "No JSON specified, please specify valid JSON for the Compliance Policy..." -f Red
    
        }
    
        else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $JSON -ContentType "application/json"
            Write-Host
            Write-Host "Successfully Updated Compliance Policy" -ForegroundColor Green
    
        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}

Function Get-LatestWindowsUpdatesBuild() {

    <#
    .SYNOPSIS
    This function is used to get the latest Windows Updates from the Microsoft RSS Feeds
    .DESCRIPTION
    The function pulls the RSS feed from the Microsoft RSS Feeds
    .EXAMPLE
    Get-WindowsUpdatesInfo -OS
    Gets the updates for Windows
    .NOTES
    NAME: Get-WindowsUpdatesInfo
    #>
    
    [cmdletbinding()]
    param
    (
        [ValidateSet('10', '11')]
        $OS,
        $Build
    )
  
  
    try {

        if (!$OS) {

            write-host "No OS specified, specify a valid Operating System number" -f Red
            break
    
        }
    
  
        else {
            if ($OS -eq '10') {
                $uri = "https://support.microsoft.com/en-us/feed/atom/6ae59d69-36fc-8e4d-23dd-631d98bf74a9"
                #$uri = 'https://kbupdate.info/rss.php?windows-10'
            }
            elseif ($OS -eq '11') {
                $uri = "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
                #$uri = 'https://kbupdate.info/rss.php?windows-11'
            }
    
            [xml]$Updates = (Invoke-WebRequest -Uri $uri -UseBasicParsing -ContentType "application/xml").Content -replace "[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000-x10FFFF]", ""
            
            $BuildVersions = @()

            foreach ($Update in $Updates.feed.entry) {
                if (($update.title.'#text' -like "*$Build*") -and ($update.title.'#text' -notlike "*Preview*") -and ($update.title.'#text' -notlike "*Out-of-band*")) {
                    $BuildVersions += $update.title.'#text'
                }
            }
            write-host
            write-host "Latest OS Build - $($BuildVersions[0])" -ForegroundColor Cyan
            $BuildVersions[0].Substring($BuildVersions[0].LastIndexOf(".")) -replace "[')', '.']", ""

        }
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
    }
    
}


#region Authentication

write-host

# Checking if authToken exists before running authentication
if ($global:authToken) {

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

    if ($TokenExpires -le 0) {

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

        # Defining User Principal Name if not present

        if ($null -eq $User -or $User -eq "") {

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

        }

        $global:authToken = Get-AuthToken -User $User

    }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if ($null -eq $User -or $User -eq "") {

        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host

    }

    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User

}

#endregion

$Date = Get-Date
$Description = "Updated Operating System Device Compliance Policy on $Date"

$Update = New-Object -TypeName psobject
$Update | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.windows10CompliancePolicy'
$Update | Add-Member -MemberType NoteProperty -Name 'description' -Value $Description

$OSCompliancePolicies = Get-DeviceCompliancePolicy | Where-Object { ($_.'@odata.type').contains("windows10CompliancePolicy") -and ($_.validOperatingSystemBuildRanges) -ne "" }
foreach ($OSCompliancePolicy in $OSCompliancePolicies) {
    Write-Host
    Write-Host "Updating Operating System Device Compliance Policy - $($OSCompliancePolicy.displayname)" -ForegroundColor Green
    $OSBuilds = $OSCompliancePolicy.validOperatingSystemBuildRanges
    $OSUpdates = @()
        
    foreach ($OSBuild in $OSBuilds) {
        if ($OSBuild.lowestVersion -like '*10.0.1*') {
            $WindowsVersion = '10'
        }
        elseif ($OSbuild.lowestVersion -like '*10.0.2*') {
            $WindowsVersion = '11'
        }
    
        $OSVersion = $OSBuild.lowestVersion.Split('.')[2]
        $BuildVersion = Get-LatestWindowsUpdatesBuild -OS $WindowsVersion -Build $OSVersion
        $NewOSBuildVersion = '10.0.' + $OSVersion + '.' + $BuildVersion
        Write-Host
        Write-Host "Updating OS Build Minimum version to - $NewOSBuildVersion" -ForegroundColor Green
    
        $OSUpdate = New-Object -TypeName psobject
        $OSUpdate | Add-Member -MemberType NoteProperty -Name 'description' -Value $OSBuild.description
        $OSUpdate | Add-Member -MemberType NoteProperty -Name 'lowestVersion' -Value $NewOSBuildVersion
        $OSUpdate | Add-Member -MemberType NoteProperty -Name 'highestVersion' -Value $OSBuild.highestVersion
        $OSUpdates += $OSUpdate
    
    }
    
    # Creating JSON object to pass to Graph
    $Update | Add-Member -MemberType NoteProperty -Name 'validOperatingSystemBuildRanges' -Value @($OSUpdates)
    $JSON = $Update | ConvertTo-Json -Depth 3
    
    # Updating the compliance policy
    Update-DeviceCompliancePolicy -Id $OSCompliancePolicy.id -JSON $JSON
}    