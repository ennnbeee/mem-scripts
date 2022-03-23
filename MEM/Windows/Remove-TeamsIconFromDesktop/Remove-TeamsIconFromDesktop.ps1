$Desktop = [Environment]::GetFolderPath("Desktop")
Remove-item -path $Desktop\* -filter "Microsoft Teams*.lnk"