$SiteCode = 'SOA'

Function Set-SMSDrive {
	$CMModulePath = $Env:SMS_ADMIN_UI_PATH.ToString().SubString(0, $Env:SMS_ADMIN_UI_PATH.Length - 5) `
	+ "\ConfigurationManager.psd1"
	Import-Module $CMModulePath -force
	Set-Location "$Sitecode`:"
}

Function Get-LimitingCollection
{
	$limitingcollection = @(Get-CMDeviceCollection | Select-Object Name, CollectionID | Out-GridView -PassThru -Title "Wait for all collections to load, then select the Limiting Device Collection. Use The ENTER Key or Mouse \ OK Button.")
    $limitingcollectionname = $limitingcollection.Name
	$limitingcollectionid = $limitingcollection.CollectionID
	If ($limitingcollection.Count -ne 1) { . Get-LimitingCollection }
}

Set-SMSDrive
Get-LimitingCollection
$Collectionstomodify = @(Get-CMDeviceCollection | Select-Object Name, LimitToCollectionName, LimitToCollectionID, MemberCount, RefreshType, ServiceWindowsCount | Out-GridView -PassThru -Title "Select Which Collections You Would Like To Modify, use the ENTER key or Mouse / OK button.")

foreach ($Collection in $Collectionstomodify)
		{
			$Collectionname = $Collection.Name
			$CollectionQuery = Get-WmiObject -Namespace ROOT\SMS\Site_$SiteCode -Class SMS_Collection -Filter "Name='$Collectionname'"			
			$CollectionQuery.LimitToCollectionName = $limitingcollection.Name
			$CollectionQuery.LimitToCollectionID = $limitingcollection.CollectionID
			$CollectionQuery.Put()
			If ($? -eq 'True')
			    {
                    Write-Host "Successfully Modified Collection $Collectionname" -foregroundcolor Green
			    }
			else
			    {
				    Write-Host "Failed to Modify Collection $Collectionname" -foregroundcolor Yellow
			    }
        	}