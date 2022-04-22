
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

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
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
        if ($AadModule -eq $null) {
    
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
                $aadModule = $AadModule | select -Unique
    
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
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
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
    
    ####################################################
    
    Function Get-DeviceCompliancePolicy(){
    
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
    
    param
    (
        $Name,
        [switch]$Android,
        [switch]$iOS,
        [switch]$Win10
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
    
        try {
    
            $Count_Params = 0
    
            if($Android.IsPresent){ $Count_Params++ }
            if($iOS.IsPresent){ $Count_Params++ }
            if($Win10.IsPresent){ $Count_Params++ }
            if($Name.IsPresent){ $Count_Params++ }
    
            if($Count_Params -gt 1){
    
            write-host "Multiple parameters set, specify a single parameter -Android -iOS or -Win10 against the function" -f Red
    
            }
    
            elseif($Android){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("android") }
    
            }
    
            elseif($iOS){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("ios") }
    
            }
    
            elseif($Win10){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("windows10CompliancePolicy") }
    
            }
    
            elseif($Name){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
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
    
    ####################################################
    
    Function Get-DeviceCompliancePolicyAssignment(){
    
    <#
    .SYNOPSIS
    This function is used to get device compliance policy assignment from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets a device compliance policy assignment
    .EXAMPLE
    Get-DeviceCompliancePolicyAssignment -id $id
    Returns any device compliance policy assignment configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicyAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Device Compliance Policy you want to check assignment")]
        $id
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceCompliancePolicies"
    
        try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
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
    
    ####################################################
    
    Function Get-AADGroup(){
    
    <#
    .SYNOPSIS
    This function is used to get AAD Groups from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Groups registered with AAD
    .EXAMPLE
    Get-AADGroup
    Returns all users registered with Azure AD
    .NOTES
    NAME: Get-AADGroup
    #>
    
    [cmdletbinding()]
    
    param
    (
        $GroupName,
        $id,
        [switch]$Members
    )
    
    # Defining Variables
    $graphApiVersion = "v1.0"
    $Group_resource = "groups"
    
        try {
    
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=id eq '$id'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
            }
    
            elseif($GroupName -eq "" -or $GroupName -eq $null){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
            }
    
            else {
    
                if(!$Members){
    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
                }
    
                elseif($Members){
    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
                $Group = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
                    if($Group){
    
                    $GID = $Group.id
    
                    $Group.displayName
                    write-host
    
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
                    }
    
                }
    
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
    
    ####################################################
    
    Function Remove-DeviceCompliancePolicy(){

        <#
        .SYNOPSIS
        This function is used to delete a device configuration policy from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and deletes a device compliance policy
        .EXAMPLE
        Remove-DeviceConfigurationPolicy -id $id
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Remove-DeviceConfigurationPolicy
        #>
        
        [cmdletbinding()]
        
        param
        (
            $id
        )
        
        $graphApiVersion = "Beta"
        $Resource = "deviceManagement/deviceCompliancePolicies"
        
            try {
        
                if($id -eq "" -or $id -eq $null){
        
                write-host "No id specified for device compliance, can't remove compliance policy..." -f Red
                write-host "Please specify id for device compliance policy..." -f Red
                break
        
                }
        
                else {
        
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
                Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete
        
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
    
    ####################################################

    #region Authentication
    
    write-host
    
    # Checking if authToken exists before running authentication
    if($global:authToken){
    
        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()
    
        # If the authToken exists checking when it expires
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
    
            if($TokenExpires -le 0){
    
            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            write-host
    
                # Defining User Principal Name if not present
    
                if($User -eq $null -or $User -eq ""){
    
                $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
                Write-Host
    
                }
    
            $global:authToken = Get-AuthToken -User $User
    
            }
    }
    
    # Authentication doesn't exist, calling Get-AuthToken function
    
    else {
    
        if($User -eq $null -or $User -eq ""){
    
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        Write-Host
    
        }
    
    # Getting the authorization token
    $global:authToken = Get-AuthToken -User $User
    
    }
    
    #endregion
    
    ####################################################
    $Date = Get-Date -Format MMMM_yyyy
    $JSON_OS = @"
            {
                "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
                "description":  "Compliance Policy for Updated Windows Operating System Builds, updated for $date",
                "displayName":  "Compliance_Windows_Corporate_OS_Build_$date",
                "passwordRequired":  false,
                "passwordBlockSimple":  false,
                "passwordRequiredToUnlockFromIdle":  false,
                "passwordMinutesOfInactivityBeforeLock":  null,
                "passwordExpirationDays":  null,
                "passwordMinimumLength":  null,
                "passwordMinimumCharacterSetCount":  null,
                "passwordRequiredType":  "deviceDefault",
                "passwordPreviousPasswordBlockCount":  null,
                "requireHealthyDeviceReport":  false,
                "osMinimumVersion":  null,
                "osMaximumVersion":  null,
                "mobileOsMinimumVersion":  null,
                "mobileOsMaximumVersion":  null,
                "earlyLaunchAntiMalwareDriverEnabled":  false,
                "bitLockerEnabled":  false,
                "secureBootEnabled":  false,
                "codeIntegrityEnabled":  false,
                "storageRequireEncryption":  false,
                "activeFirewallRequired":  false,
                "defenderEnabled":  false,
                "defenderVersion":  null,
                "signatureOutOfDate":  false,
                "rtpEnabled":  false,
                "antivirusRequired":  false,
                "antiSpywareRequired":  false,
                "deviceThreatProtectionEnabled":  false,
                "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
                "configurationManagerComplianceRequired":  false,
                "tpmRequired":  false,
                "deviceCompliancePolicyScript":  null,
                "validOperatingSystemBuildRanges":  [
                                                        {
                                                            "description":  "W10 1909",
                                                            "lowestVersion":  "10.0.18363.2212",
                                                            "highestVersion":  "10.0.18363.9999"
                                                        },
                                                        {
                                                            "description":  "W10 20H2",
                                                            "lowestVersion":  "10.0.19042.1645",
                                                            "highestVersion":  "10.0.19042.9999"
                                                        },
                                                        {
                                                            "description":  "W10 21H1",
                                                            "lowestVersion":  "10.0.19043.1645",
                                                            "highestVersion":  "10.0.19043.9999"
                                                        },
                                                        {
                                                            "description":  "W10 21H2",
                                                            "lowestVersion":  "10.0.19044.1645",
                                                            "highestVersion":  "10.0.19044.9999"
                                                        },
                                                        {
                                                            "description":  "W11 21H2",
                                                            "lowestVersion":  "10.0.22000.613",
                                                            "highestVersion":  "10.0.22000.9999"
                                                        }
                                                    ]
            }
"@


    $DCPs = Get-DeviceCompliancePolicy -Win10
    #$DCPs = Get-DeviceCompliancePolicy -Name 'Compliance_Windows_Corporate_OS_Build'
    foreach($DCP in $DCPs){
        if($DCP.validOperatingSystemBuildRanges -ne ''){
            Write-Host -ForegroundColor Green "Found Operating System Compliance Policy $($DCP.displayName)"
            #$JSON = ConvertTo-Json $DCP -Depth 5
            

            $DCPA = Get-DeviceCompliancePolicyAssignment -id $DCP.id
            if($DCPA){
                Write-Host -ForegroundColor Cyan "Getting Group Assignment for $($DCP.displayName)"
                if($DCPA.count -gt 1){            
                    foreach($group in $DCPA){            
                        (Get-AADGroup -id $group.target.GroupId).displayName
                        Write-Host -ForegroundColor Green "$($group.target.GroupId).displayName) assigned $($DCP.displayName)"
                    }
                }
                else{
                    (Get-AADGroup -id $DCPA.target.GroupId).displayName
                    Write-Host -ForegroundColor Green "$($group.target.GroupId).displayName) assigned $($DCP.displayName)"
                }
            
            }
        }
    }
