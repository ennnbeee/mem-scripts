$SiteCode = 'SOA'
$SiteServer = 'sccm01'

Function Create-SMSDRIVE {
	$CMModulePath = $Env:SMS_ADMIN_UI_PATH.ToString().SubString(0, $Env:SMS_ADMIN_UI_PATH.Length - 5) `
	+ "\ConfigurationManager.psd1"
	Import-Module $CMModulePath -force
	Set-Location "$Sitecode`:"
}

Function Get-LimitingCollection
{
	$limitingcollection = @(Get-CMDeviceCollection | Select-Object Name, CollectionID | Out-GridView -PassThru -Title "Select You're Limiting Device Collection, Use The ENTER Key or Mouse \ OK Button.")
	$limitingcollectionname = $limitingcollection.Name
	$limitingcollectionid = $limitingcollection.CollectionID
	If ($limitingcollection.Count -ne 1) { . GET-LimitingCollection }
}

Create-SMSDRIVE
Get-LimitingCollection
$Collectionstomodify = @(Get-CMDeviceCollection | Select-Object Name, LimitToCollectionName, LimitToCollectionID, MemberCount, RefreshType, ServiceWindowsCount | Out-GridView -PassThru -Title "Select Which Collections You Would Like To Modify, use the ENTER key or Mouse / OK button.")

foreach ($Collection in $Collectionstomodify)
		{
			$Collectionname = $Collection.Name
			$CollectionQuery = Get-WmiObject -Namespace ROOT\SMS\Site_$SiteCode -Class SMS_Collection -Filter "Name='$Collectionname'"			
			$CollectionQuery.LimitToCollectionName = $limitingcollectionname
			$CollectionQuery.LimitToCollectionID = $limitingcollectionid
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