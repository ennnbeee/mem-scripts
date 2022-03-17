[CmdletBinding()]
	param(
        [Parameter(ParameterSetName='cmdline')]
        [switch] $Windows,
        [switch] $Android,
        [switch] $iOS,
        [switch] $macOS,
        [switch] $Defender,
        [Switch] $DefenderforEndpoint,
        [Switch] $NCSC,
        [Switch] $CSE,
        [Switch] $CoManaged
	)

##Functions
#MS Functions
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
    
    if($userUpn.Host -like "*onmicrosoft.com*"){
        $tenant = Read-Host -Prompt "Please specify your Tenant name i.e. company.com"
        Write-Host
    }
    else{
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
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
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
Function Test-JSON(){

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
        
            if (!$validJson){
            
            Write-Host "Provided JSON isn't in valid JSON format" -f Red
            break
        
            }
        
}
Function Add-DeviceCompliancePolicy(){

    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
        
        try {
    
            if($JSON -eq "" -or $JSON -eq $null){
    
            write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red
    
            }
    
            else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
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
Function Add-DeviceConfigurationPolicy(){

    <#
    .SYNOPSIS
    This function is used to add an device configuration policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy
    .EXAMPLE
    Add-DeviceConfigurationPolicy -JSON $JSON
    Adds a device configuration policy in Intune
    .NOTES
    NAME: Add-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    Write-Verbose "Resource: $DCP_resource"
    
        try {
    
            if($JSON -eq "" -or $JSON -eq $null){
    
            write-host "No JSON specified, please specify valid JSON for the Device Configuration Policy..." -f Red
    
            }
    
            else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
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
Function Get-EndpointSecurityTemplate(){

    <#
    .SYNOPSIS
    This function is used to get all Endpoint Security templates using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets all Endpoint Security templates
    .EXAMPLE
    Get-EndpointSecurityTemplate 
    Gets all Endpoint Security Templates in Endpoint Manager
    .NOTES
    NAME: Get-EndpointSecurityTemplate
    #>
    
    
    $graphApiVersion = "Beta"
    $ESP_resource = "deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"
    
        try {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
            (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value
    
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
Function Add-EndpointSecurityPolicy(){

    <#
    .SYNOPSIS
    This function is used to add an Endpoint Security policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds an Endpoint Security  policy
    .EXAMPLE
    Add-EndpointSecurityDiskEncryptionPolicy -JSON $JSON -TemplateId $templateId
    Adds an Endpoint Security Policy in Endpoint Manager
    .NOTES
    NAME: Add-EndpointSecurityPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $TemplateId,
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $ESP_resource = "deviceManagement/templates/$TemplateId/createInstance"
    Write-Verbose "Resource: $ESP_resource"
    
        try {
    
            if($JSON -eq "" -or $JSON -eq $null){
    
            write-host "No JSON specified, please specify valid JSON for the Endpoint Security Policy..." -f Red
    
            }
    
            else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
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

Function Add-ManagedAppPolicy(){

    <#
    .SYNOPSIS
    This function is used to add an Managed App policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a Managed App policy
    .EXAMPLE
    Add-ManagedAppPolicy -JSON $JSON
    Adds a Managed App policy in Intune
    .NOTES
    NAME: Add-ManagedAppPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/managedAppPolicies"
    
        try {
    
            if($JSON -eq "" -or $JSON -eq $null){
    
            write-host "No JSON specified, please specify valid JSON for a Managed App Policy..." -f Red
    
            }
    
            else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
            }
    
        }
    
        catch {
    
        Write-Host
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
    
Function Add-IntuneFilter(){


[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/assignmentFilters"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Device Configuration Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

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


#Custom Functions
Function Set-MEMGroups{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$CSVPath
	)

    $aadgroups = Import-Csv -Path $CSVPath
    foreach($aadgroup in $aadgroups){
        $group = Get-AzureADGroup -SearchString $aadgroup.DisplayName
        if($null -eq $group){
            if($aadgroup.GroupTypes -eq "DynamicMembership"){
                try{
                    New-AzureADMSGroup -DisplayName $aadgroup.DisplayName -MailNickname $aadgroup.DisplayName -Description $aadgroup.Description -MailEnabled $false -SecurityEnabled $true -GroupTypes $aadgroup.GroupTypes -MembershipRule $aadgroup.MembershipRule -membershipRuleProcessingState "On" | out-null
                    Write-Host -ForegroundColor Green "Dynamic Group $($aadgroup.DisplayName) created"       
                }
                catch{
                    Write-Host -ForegroundColor Red "Dynamic Group $($aadgroup.DisplayName) not created" 
                }
            }
            else{
                try{
                    New-AzureADMSGroup -DisplayName $aadgroup.DisplayName -MailNickname $aadgroup.DisplayName -Description $aadgroup.Description -MailEnabled $false -SecurityEnabled $true | out-null
                    Write-Host -ForegroundColor Green "Group $($aadgroup.DisplayName) created"       
                }
                catch{
                    Write-Host -ForegroundColor Red "Group $($aadgroup.DisplayName) Group not created" 
                }    
            }
        }
        else{
            write-host -ForegroundColor Cyan "Group $($aadgroup.DisplayName) already exists"
        }

     }

}
Function Set-MEMCompliance{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$CompliancePath
	)
    

    $Files = Get-ChildItem -Path $CompliancePath

    foreach($file in $files){
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version
        $DisplayName = $JSON_Convert.displayName
        $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
        
        # Adding Scheduled Actions Rule to JSON
        $scheduledActionsForRule = '"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]'        
        $JSON_Output = $JSON_Output.trimend("}")
        $JSON_Output = $JSON_Output.TrimEnd() + "," + "`r`n"
        # Joining the JSON together
        $JSON_Output = $JSON_Output + $scheduledActionsForRule + "`r`n" + "}"
        Write-Host "Adding Compliance Policy '$DisplayName'" -ForegroundColor Cyan
        Add-DeviceCompliancePolicy -JSON $JSON_Output
        Write-Host "Sucessfully Added Compliance Policy '$DisplayName'" -ForegroundColor Green
    }

    

}
Function Set-MEMConfiguration{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$ConfigurationPath
	)
    

    $Files = Get-ChildItem -Path $ConfigurationPath

    foreach($file in $files){
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,supportsScopeTags
        $DisplayName = $JSON_Convert.displayName
        $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
        Write-Host "Adding Device Configuration Policy '$DisplayName'" -ForegroundColor Cyan
        Add-DeviceConfigurationPolicy -JSON $JSON_Output
        Write-Host "Sucessfully Added Configuration Profile '$DisplayName'" -ForegroundColor Green
    }

    

}
Function Set-MEMEndpointSecurity{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$EndpointSecurityPath
	)
    

    $Files = Get-ChildItem -Path $EndpointSecurityPath
    
    foreach($file in $files){
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json
        $JSON_DN = $JSON_Convert.displayName
        $JSON_TemplateDisplayName = $JSON_Convert.TemplateDisplayName
        $JSON_TemplateId = $JSON_Convert.templateId

        Write-Host "Endpoint Security Policy '$JSON_DN' found..." -ForegroundColor Cyan
        Write-Host "Template Display Name: $JSON_TemplateDisplayName"
        Write-Host "Template ID: $JSON_TemplateId"
        $Templates = Get-EndpointSecurityTemplate
        $ES_Template = $Templates | Where-Object  { $_.id -eq $JSON_TemplateId }

        # If template is a baseline Edge, MDATP or Windows, use templateId specified
        if(($ES_Template.templateType -eq "microsoftEdgeSecurityBaseline") -or ($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")){

            $TemplateId = $JSON_Convert.templateId

        }

        # Else If not a baseline, check if template is deprecated
        elseif($ES_Template){

            # if template isn't deprecated use templateId
            if($ES_Template.isDeprecated -eq $false){

                $TemplateId = $JSON_Convert.templateId

            }

            # If template deprecated, look for lastest version
            elseif($ES_Template.isDeprecated -eq $true) {

                $Template = $Templates | Where-Object { $_.displayName -eq "$JSON_TemplateDisplayName" }

                $Template = $Template | Where-Object { $_.isDeprecated -eq $false }

                $TemplateId = $Template.id

            }

        }

        # Else If Imported JSON template ID can't be found check if Template Display Name can be used
        elseif($null -eq $ES_Template){

            Write-Host "Didn't find Template with ID $JSON_TemplateId, checking if Template DisplayName '$JSON_TemplateDisplayName' can be used..." -ForegroundColor Yellow
            $ES_Template = $Templates | Where-Object  { $_.displayName -eq "$JSON_TemplateDisplayName" }

            If($ES_Template){

                if(($ES_Template.templateType -eq "securityBaseline") -or ($ES_Template.templateType -eq "advancedThreatProtectionSecurityBaseline")){

                    Write-Host
                    Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Yellow
                    Write-Host "Importing using the updated template could fail as settings specified may not be included in the latest template..." -ForegroundColor Yellow
                    Write-Host
                    break

                }

                else {

                   $Template = $ES_Template | Where-Object { $_.isDeprecated -eq $false }

                    $TemplateId = $Template.id

                }

            }

            else {

                Write-Host
                Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Red
                Write-Host "Importing using the updated template could fail as settings specified may not be included in the latest template..." -ForegroundColor Red
                Write-Host
                

            }

        }

        # Excluding certain properties from JSON that aren't required for import
        $JSON_Convert = $JSON_Convert | Select-Object -Property * -ExcludeProperty TemplateDisplayName,TemplateId,versionInfo

        $DisplayName = $JSON_Convert.displayName

        $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5

        Write-Host "Adding Endpoint Security Policy '$DisplayName'" -ForegroundColor Cyan
        Add-EndpointSecurityPolicy -TemplateId $TemplateId -JSON $JSON_Output
        Write-Host "Sucessfully Added Endpoint Security Profile '$DisplayName'" -ForegroundColor Green
    }

    

}
Function Set-MEMUpdates{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$UpdatePath
	)
    

    $Files = Get-ChildItem -Path $UpdatePath

    foreach($file in $files){
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,'groupAssignments@odata.context',groupAssignments,supportsScopeTags
        $DisplayName = $JSON_Convert.displayName
        $JSON_Output = $JSON_Convert | ConvertTo-Json
        Write-Host "Adding Software Update Policy '$DisplayName'" -ForegroundColor Cyan
        Add-DeviceConfigurationPolicy -JSON $JSON_Output
        Write-Host "Sucessfully Added Software Update Profile '$DisplayName'" -ForegroundColor Green
    }

    

}
Function Set-MEMFilters{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$FilterPath
	)
    

    $Files = Get-ChildItem -Path $FilterPath

    foreach($file in $files){
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,roleScopeTags
        $DisplayName = $JSON_Convert.displayName
        $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
        Write-Host "Adding Intune Filter '$DisplayName'" -ForegroundColor Cyan
        Add-IntuneFilter -JSON $JSON_Output
        Write-Host "Sucessfully Added Intune Filter '$DisplayName'" -ForegroundColor Green
    }

    

}
Function Set-MAMSettings{
    [CmdletBinding()]
	param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[string[]]$MAMPath
	)
    

    $Files = Get-ChildItem -Path $MAMPath

    foreach($file in $files){
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id,createdDateTime,lastModifiedDateTime,version,"@odata.context",apps@odata.context,deployedAppCount
        $JSON_Apps = $JSON_Convert.apps | Select-Object * -ExcludeProperty id,version
        $JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
        $DisplayName = $JSON_Convert.displayName
        $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
        Write-Host "Adding App Protection Policy '$DisplayName'" -ForegroundColor Cyan
        Add-ManagedAppPolicy -JSON $JSON_Output
        Write-Host "Sucessfully App Protection Policy '$DisplayName'" -ForegroundColor Green
    }

    

}

#Script Start
Import-Module AzureADPreview
$AzureADcreds = Get-Credential
Connect-AzureAD -Credential $AzureADcreds


#MEM Settings
#Connect to Graph
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

            if($null -eq $User -or $User -eq ""){

            #$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            #Write-Host
            $User = $AzureADcreds.UserName

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function
else {

    if($null -eq $User -or $User -eq ""){

        #$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        #Write-Host
        $User = $AzureADcreds.UserName

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}


#Groups
Set-MEMGroups -CSVPath "C:\Source\Scripts\MEM\Deploy\Templates\AAD_Groups\AAD_Groups.csv"
Set-MEMGroups -CSVPath "C:\Source\Scripts\MEM\Deploy\Templates\AAD_Groups\AAD_Groups_Test.csv"

#Windows
if($Windows){
    Set-MEMGroups -CSVPath "C:\Source\Scripts\MEM\Deploy\Templates\AAD_Groups\AAD_Groups_Windows.csv"
    Set-MEMCompliance -CompliancePath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Compliance"
    Set-MEMConfiguration -ConfigurationPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Configuration"
    Set-MEMUpdates -UpdatePath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Updates"
    Set-MEMEndpointSecurity -EndpointSecurityPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Endpoint_Security"
    Set-MEMFilters -FilterPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Filters"
    
    if($CoManaged){
        Set-MEMConfiguration -ConfigurationPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Configuration\CoManaged"
    }

    if($Defender){
        Set-MEMCompliance -CompliancePath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Compliance\Defender"
        Set-MEMEndpointSecurity -EndpointSecurityPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Endpoint_Security\Defender"

    }

    if($DefenderforEndpoint){
        Set-MEMCompliance -CompliancePath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Compliance\Defender"
        Set-MEMEndpointSecurity -EndpointSecurityPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Endpoint_Security\Defender"
        Set-MEMConfiguration -ConfigurationPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Configuration\DefenderforEndpoint"
    }

    if($NCSC){
        Set-MEMEndpointSecurity -EndpointSecurityPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Endpoint_Security\NCSC"
        Set-MEMConfiguration -ConfigurationPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Configuration\NCSC"
    }

    if($CSE){
        Set-MEMEndpointSecurity -EndpointSecurityPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Endpoint_Security\CSE"
        Set-MEMConfiguration -ConfigurationPath "C:\Source\Scripts\MEM\Deploy\Templates\Windows\Configuration\CSE"
    }
}

#Android
if($Android){
    Set-MEMGroups -CSVPath "C:\Source\Scripts\MEM\Deploy\Templates\AAD_Groups\AAD_Groups_Android.csv"
    Set-MEMCompliance -CompliancePath "C:\Source\Scripts\MEM\Deploy\Templates\Android\Compliance"
    Set-MEMConfiguration -ConfigurationPath "C:\Source\Scripts\MEM\Deploy\Templates\Android\Configuration"
    Set-MEMFilters -FilterPath "C:\Source\Scripts\MEM\Deploy\Templates\Android\Filters"
    Set-MAMSettings -MAMPath "C:\Source\Scripts\MEM\Deploy\Templates\Android\MAM"
    
    if($DefenderforEndpoint){

    }
}

#iOS
if($iOS){
    Set-MEMGroups -CSVPath "C:\Source\Scripts\MEM\Deploy\Templates\AAD_Groups\AAD_Groups_iOS.csv"
    Set-MEMCompliance -CompliancePath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\Compliance"
    Set-MEMConfiguration -ConfigurationPath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\Configuration"
    Set-MEMUpdates -UpdatePath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\Updates"
    Set-MEMFilters -FilterPath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\Filters"
    Set-MAMSettings -MAMPath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\MAM"

    if($DefenderforEndpoint){

    }
}
#macOS
if($macOS){
    Set-MEMGroups -CSVPath "C:\Source\Scripts\MEM\Deploy\Templates\AAD_Groups\AAD_Groups_macOS.csv"
    Set-MEMCompliance -CompliancePath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\Compliance"
    Set-MEMConfiguration -ConfigurationPath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\Configuration"
    Set-MEMEndpointSecurity -EndpointSecurityPath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\Endpoint_Security"
    Set-MEMFilters -FilterPath "C:\Source\Scripts\MEM\Deploy\Templates\iOS\Filters"

    if($DefenderforEndpoint){

    }
}

#Adds group membership
$MEMGroups = Get-AzureADGroup -SearchString "SG_"
$TestComputersGroup = Get-AzureADGroup -SearchString "SG_MEM_TEST_Devices"
$TestUsersGroup = Get-AzureADGroup -SearchString "SG_MEM_TEST_Users"

foreach($MEMGroup in $MEMGroups){
    if($MEMGroup.DisplayName -like "SG*Devices*POC"){
        Add-AzureADGroupMember -ObjectId $MEMGroup.ObjectId -RefObjectId $TestComputersGroup.ObjectId
        Write-Host -ForegroundColor Cyan "Added $($TestComputersGroup.DisplayName) to $($MEMGroup.DisplayName)" 

    }
    if($MEMGroup.DisplayName -like "SG*Users*POC" -or $MEMGroup.DisplayName -like "SG_AAD_*POC"-or $MEMGroup.DisplayName -like "SG_MAM_*POC"){
        Add-AzureADGroupMember -ObjectId $MEMGroup.ObjectId -RefObjectId $TestUsersGroup.ObjectId
        Write-Host -ForegroundColor Cyan "Added $($TestUsersGroup.DisplayName) to $($MEMGroup.DisplayName)" 
    }
}
