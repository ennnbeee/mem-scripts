#Reg Settings
$RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"

$LockScreenPath = "LockScreenImagePath"
$LockScreenStatus = "LockScreenImageStatus"
$LockScreenUrl = "LockScreenImageUrl"
$WallpaperPath = "DesktopImagePath"
$WallpaperStatus = "DesktopImageStatus"
$WallpaperUrl = "DesktopImageUrl"

$StatusValue = "1"

#Customistion
$directory = "C:\Windows\Web\Wallpaper\Custom"

$wallpaperaddress = "https://www.ucsd.ac.uk/wp-content/uploads/Torbay-council-feature-image.png"
$WallpaperDirectory = $directory + "\wallpaper.png"
$lockscreenaddress = "https://www.britishports.org.uk/content/uploads/2016/02/tor_bay_harbour.jpg"
$LockscreenDirectory = $directory + "\lockscreen.jpg"





If ((Test-Path -Path $directory) -eq $false)
{
	New-Item -Path $directory -ItemType directory
}

#Downloads files
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($wallpaperaddress, $WallpaperDirectory)
$wc.DownloadFile($lockscreenaddress, $LockscreenDirectory)


if (!(Test-Path $RegKeyPath))
{
	Write-Host "Creating registry path $($RegKeyPath)."
	New-Item -Path $RegKeyPath -Force | Out-Null
}

#Sets Lockscreen
New-ItemProperty -Path $RegKeyPath -Name $LockScreenStatus -Value $StatusValue -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $RegKeyPath -Name $LockScreenPath -Value $LockscreenDirectory -PropertyType STRING -Force | Out-Null
New-ItemProperty -Path $RegKeyPath -Name $LockScreenUrl -Value $LockscreenDirectory -PropertyType STRING -Force | Out-Null

#Sets Wallpaper
New-ItemProperty -Path $RegKeyPath -Name $WallpaperStatus -Value $StatusValue -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $RegKeyPath -Name $WallpaperPath -Value $WallpaperDirectory -PropertyType STRING -Force | Out-Null
New-ItemProperty -Path $RegKeyPath -Name $WallpaperUrl -Value $WallpaperDirectory -PropertyType STRING -Force | Out-Null

RUNDLL32.EXE USER32.DLL, UpdatePerUserSystemParameters 1, True