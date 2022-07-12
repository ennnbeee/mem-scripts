$os = [System.Environment]::OSVersion.Version
$LanguageList = New-WinUserLanguageList -Language 'en-GB'
$Languages  = New-Object -TypeName System.Collections.ArrayList
$Languages.AddRange(@(
        "en-US",
        "ar-SA",
        "zh-HK",
        "zh-CN",
        "zh-TW",
        "el-GR",
        "he-IL",
        "ja-JP",
        "ko-KR",
        "zh-Hant-TW",
        "jp-JP",
        "am-ET",
        "Cy-az-AZ",
        "Lt-az-AZ",
        "fa-IR",
        "ka-GE",
        "el-GR",
        "gu-IN",
        "he-IL",
        "ru-KG",
        "ru-KZ",
        "mn-MN",
        "pa-IN",
        "ta-IN",
        "th-TH",
        "tr-TR",
        "ur-PK",
        "uz-Cyrl",
        "vi-VN"
    ))



if($os.Major -eq '10'){
    Foreach($Language in $Languages){
        $LanguageList.Add($Language)
    }

Set-WinUserLanguageList -LanguageList $LanguageList -Force


}
else{
    
}