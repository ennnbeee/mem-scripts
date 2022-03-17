
#Load Modules
if (Get-Module -ListAvailable -Name AzureAD) {
    Write-Host "AzureAD Module Already Installed" -ForegroundColor Green
} 
else {
    Write-Host "AzureAD Module Not Installed. Installing........." -ForegroundColor Red
        Install-Module -Name AzureAD -AllowClobber -Force
    Write-Host "AzureAD Module Installed" -ForegroundColor Green
}
Import-Module AzureAD

##Tenant Default
#AAD Groups

$aadgroups = Import-Csv -Path "C:\Source\Scripts\MEM\Deploy\Templates\AAD_Groups\AAD_Groups.csv"

foreach($aadgroup in $aadgroups){
    if($aadgroup.GroupTypes -eq "DynamicMembership"){
        try{
            New-AzureADMSGroup -DisplayName $aadgroup.DisplayName -Description $aadgroup.Description -MailEnabled $false -SecurityEnabled $true -GroupTypes $aadgroup.GroupTypes -MembershipRule $aadgroup.MembershipRule
            Write-Host -ForegroundColor Green "$($aadgroup.DisplayName) Dynamic Group created"       
        }
        catch{
            Write-Host -ForegroundColor Red "$($aadgroup.DisplayName) Dynamic Group not-created" 
        }
    }
    else{
        try{
            New-AzureADMSGroup -DisplayName $aadgroup.DisplayName -Description $aadgroup.Description -MailEnabled $false -SecurityEnabled $true
            Write-Host -ForegroundColor Green "$($aadgroup.DisplayName)  Group created"       
        }
        catch{
            Write-Host -ForegroundColor Red "$($aadgroup.DisplayName) Group not-created" 
        }    
    }
    
    

}

