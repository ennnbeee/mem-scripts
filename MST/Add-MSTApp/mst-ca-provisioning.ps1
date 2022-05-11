# -----------------------------------------------------------------------
# Copyright © Microsoft Corporation. All rights reserved.
# 
# mst-CA-readiness - Provisions a service principal for Microsoft Tunnel
# -----------------------------------------------------------------------
param (
    [parameter(Mandatory=$false)]
    [String]$AADEnvironment
)

Import-Module -Name AzureAD

if ($AADEnvironment -ieq "onedf" -or $AADEnvironment -ieq "df" -or $AADEnvironment -ieq "internal") {
    try {
        Connect-AzureAD -AzureEnvironmentName AzurePPE
    } catch [Exception] {
        Write-Error "Error occured connecting to AAD"
        echo $_.Exception.GetType().FullName, $_.Exception.Message
        Write-Host "Failed to provision the Service Principal" -ForegroundColor Red
        exit 1
    }
} elseif ($AADEnvironment -ieq "germany" -or $AADEnvironment -ieq "blackforest" ) {
    try {
        Connect-AzureAD -AzureEnvironmentName AzureGermanyCloud
    } catch [Exception] {
        Write-Error "Error occured connecting to AAD"
        echo $_.Exception.GetType().FullName, $_.Exception.Message
        Write-Host "Failed to provision the Service Principal" -ForegroundColor Red
        exit 1
    }
} elseif ($AADEnvironment -ieq "government" -or $AADEnvironment -ieq "fairfax" ) {
    try {
        Connect-AzureAD -AzureEnvironmentName AzureUSGovernment
    } catch [Exception] {
        Write-Error "Error occured connecting to AAD"
        echo $_.Exception.GetType().FullName, $_.Exception.Message
        Write-Host "Failed to provision the Service Principal" -ForegroundColor Red
        exit 1
    }
} elseif ($AADEnvironment -ieq "china" -or $AADEnvironment -ieq "mooncake" ) {
    try {
        Connect-AzureAD -AzureEnvironmentName AzureChinaCloud
    } catch [Exception] {
        Write-Error "Error occured connecting to AAD"
        echo $_.Exception.GetType().FullName, $_.Exception.Message
        Write-Host "Failed to provision the Service Principal" -ForegroundColor Red
        exit 1
    }
} else  {
    try {
        Connect-AzureAD
    } catch [Exception] {
        Write-Error "Error occured connecting to AAD"
        echo $_.Exception.GetType().FullName, $_.Exception.Message
        Write-Host "Failed to provision the Service Principal" -ForegroundColor Red
        exit 1
    }
}

try {
    $appId = "3678c9e9-9681-447a-974d-d19f668fcd88"
    
    New-AzureADServicePrincipal -AppId $appId
    $result = Get-AzureADServicePrincipal -Filter "AppID eq '$appId'"

    Write-Host $result

    $displayName = $result.AppDisplayName
    Write-Host "Successfully provisioned the Service Principal for $displayName" -ForegroundColor Green
} catch [Exception] {
    Write-Error "Error provisioning Service Principal"
    echo $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Host "Failed to provision the Service Principal" -ForegroundColor Red
    exit 1
}