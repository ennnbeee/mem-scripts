$Desktop = [Environment]::GetFolderPath("Desktop")
if (-Not (Test-Path "$Desktop\Microsoft Teams*")) {
    Write-Host "Not Present"
}