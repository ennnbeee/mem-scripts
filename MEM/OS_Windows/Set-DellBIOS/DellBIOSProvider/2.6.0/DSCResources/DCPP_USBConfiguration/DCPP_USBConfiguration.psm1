# Import the helper functions

Import-Module $PSScriptRoot\..\..\Misc\helper.psm1 -Verbose:$false

function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Category
	)

	#Write-Verbose "Use this cmdlet to deliver information about command processing."

	#Write-Debug "Use this cmdlet to write debug information while troubleshooting."


	<#
	$returnValue = @{
		Category = [System.String]
		MultiCoreSupport = [System.String]
		IntelSpeedStep = [System.String]
		CStates = [System.String]
		IntelTurboBoost = [System.String]
		HyperThreadControl = [System.String]
		Password = [System.String]
		SecurePassword = [System.String]
		PathToKey = [System.String]
	}

	$returnValue
	#>
	
				   # Check if module DellBIOSprovider is already loaded. If not, load it.
   try{
    $bool = Confirm-DellPSDrive -verbose
    }
    catch 
    {
        write-Verbose $_
        $msg = "Get-TargetResource: $($_.Exception.Message)"
        Write-DellEventLog -Message $msg -EventID 1 -EntryType 'Error'
        write-Verbose "Exiting Get-TargetResource"
        return
    }
    if ($bool) {                      
        Write-Verbose "Dell PS-Drive DellSmbios is found."
    }
    else{
        $Message = “Get-TargetResource: Module DellBiosProvider was imported correctly."
        Write-DellEventLog -Message $Message -EventID 2 
    }

    $Get = get-childitem -path @("DellSmbios:\" + $Category)
     # Removing Verbose and Debug from output
    $PSBoundParameters.Remove("Verbose") | out-null
    $PSBoundParameters.Remove("Debug") | out-null

  
    $out = @{}   
    $Get | foreach-Object {$out.Add($_.Attribute, $_.CurrentValue)}
    $out.add('Category', $Category )
    $out

}


function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Category,

		[ValidateSet("Enabled","Disabled","EnabledWithNoUSBBoot")]
		[System.String]
		$UsbEmu,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsInternal,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsExternal,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$Usb30,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$DisableDockingStationDevicesexceptvideo,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsSide,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear1,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear2,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear3,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear4,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear5,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear6,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort06,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort07,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort08,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort09,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsSide1,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsSide2,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort12,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort13,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort14,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort15,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort16,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort17,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort18,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort19,		

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront1,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront2,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront3,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront4,		
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort24,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort25,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort26,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort27,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort28,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort29,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$RearUSB3_0Ports,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsInternal2,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$ThunderboltPorts,
		
		[ValidateSet("NoSec","UserAuth","SecConn","DpOnly")]
		[System.String]
		$ThunderboltSecLvl,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$ThunderboltBoot,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$ThunderboltPreboot,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AlwaysAllowDellDocks,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbRearDual,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbRearDual2Stack,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbRearQuad,	

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$FrontUsbPortCollection,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$RearUsb3Ports,		

		[System.String]
		$Password,

		[System.String]
		$SecurePassword,

		[System.String]
		$PathToKey
	)

    if (-not(CheckModuleLoaded)) {
        Write-Verbose -Message 'Required module DellBiosProvider does not exist. Exiting.'
        return $true
    }

    $DellPSDrive = get-psdrive -name Dellsmbios
    if ( !$DellPSDrive)
    {
        $Message = "Drive DellSmbios is not found. Exiting."
        Write-Verbose $Message
        Write-DellEventLog -Message $Message -EventID 3 -EntryType "Error"
        return $true
    }
    $attributes_desired = $PSBoundParameters
    $atts = $attributes_desired

    $pathToCategory = $DellPSDrive.Name + ':\' + $atts["Category"]
    
    Dir $pathToCategory -verbose

    $atts.Remove("Verbose") | out-null
    $atts.Remove("Category") | out-null
    $atts.Remove("Debug") | out-null
    $securePwd=$atts["SecurePassword"]
    $passwordSet=$atts["Password"]
    $atts.Remove("Password") | Out-Null
    $atts.Remove("SecurePassword") | Out-Null
    $pathToKey=$atts["PathToKey"]
	if(-Not [string]::IsNullOrEmpty($pathToKey))
	{  
		if(Test-Path $pathToKey)
		{
		$key=Get-Content $pathToKey
		}
		else
		{
		$key=""
		}
	}
    $atts.Remove("PathToKey") | Out-Null
    
    #foreach($a in Import-Csv((Get-DellBIOSEncryptionKey)))
    #{
   # $key+=$a
   # }
    $atts.Keys | foreach-object { 
                   # $atts[$_]
				    $path=""
                    if($($_) -eq "RearUSB3_0Ports")
                    {
                    $path = $pathToCategory + '\' + "RearUSB3.0Ports"
                    }					 

                    else
                    {
                    $path = $pathToCategory + '\' + $($_)
                    }				   
                    
                    $value = $atts[$_]
		    if(-Not [string]::IsNullOrEmpty($securePwd))
		    {                
			$pasvar=ConvertTo-SecureString $securePwd.ToString() -Key $key
            Set-Item  -path $path -value $value -verbose -ErrorVariable ev -ErrorAction SilentlyContinue -PasswordSecure $pasvar
		    }

		    elseif(-Not [string]::IsNullOrEmpty($passwordSet))
		    {
			Set-Item  -path $path -value $value -verbose -ErrorVariable ev -ErrorAction SilentlyContinue -Password $passwordSet
		    }

		    else
		    {
			Set-Item  -path $path -value $value -verbose -ErrorVariable ev -ErrorAction SilentlyContinue
		    }
                    if ( $ev) { 
                        $cmdline = $ExecutionContext.InvokeCommand.ExpandString($ev.InvocationInfo.Line)
                        $Message = "An error occured in executing " + $cmdline + "`nError message: $($ev.ErrorDetails)"
                        Write-Verbose $Message
                        Write-DellEventLog -Message $Message -EventID 5 -EntryType "Error"
                    }
                    
                 }



}


function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Category,

		[ValidateSet("Enabled","Disabled","EnabledWithNoUSBBoot")]
		[System.String]
		$UsbEmu,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsInternal,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsExternal,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$Usb30,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$DisableDockingStationDevicesexceptvideo,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsSide,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear1,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear2,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear3,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear4,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear5,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear6,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort06,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort07,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort08,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort09,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsSide1,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsSide2,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort12,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort13,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort14,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort15,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort16,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort17,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort18,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort19,		

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront1,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront2,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront3,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsFront4,		
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort24,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort25,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort26,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort27,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort28,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$USBPort29,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsRear,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$RearUSB3_0Ports,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbPortsInternal2,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$FrontUsbPortCollection,
		
		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$ThunderboltPorts,
		
		[ValidateSet("NoSec","UserAuth","SecConn","DpOnly")]
		[System.String]
		$ThunderboltSecLvl,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$ThunderboltBoot,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$ThunderboltPreboot,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$AlwaysAllowDellDocks,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbRearDual,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbRearDual2Stack,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$UsbRearQuad,	

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$FrontUsbPortCollection,

		[ValidateSet("Enabled","Disabled")]
		[System.String]
		$RearUsb3Ports,			

		[System.String]
		$Password,

		[System.String]
		$SecurePassword,

		[System.String]
		$PathToKey
	)

    $Get = Get-TargetResource $PSBoundParameters['Category'] -verbose

    New-DellEventLog
 
    $PSBoundParameters.Remove("Verbose") | out-null
    $PSBoundParameters.Remove("Debug") | out-null
    $PSBoundParameters.Remove("Category") | out-null
    $PSBoundParameters.Remove("Password") | out-null
    $PSBoundParameters.Remove("SecurePassword") | out-null

    $attributes_desired = $PSBoundParameters

    $bool = $true

    foreach ($config_att in  $PSBoundParameters.GetEnumerator())
    {
        if ($Get.ContainsKey($config_att.Key)) {
		
		     $currentvalue=""
			if($config_att.Key -match "RearUSB3_0Ports")
			{
			$currentvalue = $Get["RearUSB3.0Ports"]
			}
			else
			{
				$currentvalue = $Get[$config_att.Key]
			} 
		
            $currentvalue_nospace = $currentvalue -replace " ", ""
            if ($config_att.Value -ne $currentvalue_nospace){
                $bool = $false
                $drift  = "`nCurrentValue: $currentvalue_nospace`nDesiredValue: $($config_att.value)"
                $message = "Configuration is drifted in category $Category for $($config_att.Key). $drift"
                write-verbose $message
                Write-DellEventLog -Message $message -EventID 4 -EntryType Warning
            
            }
            else {
                write-Debug "Configuration is same for $config_att."
            }
    }
    else
    {
        $message = "Unsupported attribute $($config_att)"
        Write-Verbose $message
    }
   }
   return $bool

}


Export-ModuleMember -Function *-TargetResource


# SIG # Begin signature block
# MIIcOwYJKoZIhvcNAQcCoIIcLDCCHCgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBMoU61WYqkjzMl
# NFbNJk/L15Zs45zgy4+hMDM6ctS2CqCCCsowggUyMIIEGqADAgECAg0Ah4JSYAAA
# AABR03PZMA0GCSqGSIb3DQEBCwUAMIG+MQswCQYDVQQGEwJVUzEWMBQGA1UEChMN
# RW50cnVzdCwgSW5jLjEoMCYGA1UECxMfU2VlIHd3dy5lbnRydXN0Lm5ldC9sZWdh
# bC10ZXJtczE5MDcGA1UECxMwKGMpIDIwMDkgRW50cnVzdCwgSW5jLiAtIGZvciBh
# dXRob3JpemVkIHVzZSBvbmx5MTIwMAYDVQQDEylFbnRydXN0IFJvb3QgQ2VydGlm
# aWNhdGlvbiBBdXRob3JpdHkgLSBHMjAeFw0xNTA2MTAxMzQyNDlaFw0zMDExMTAx
# NDEyNDlaMIHIMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNRW50cnVzdCwgSW5jLjEo
# MCYGA1UECxMfU2VlIHd3dy5lbnRydXN0Lm5ldC9sZWdhbC10ZXJtczE5MDcGA1UE
# CxMwKGMpIDIwMTUgRW50cnVzdCwgSW5jLiAtIGZvciBhdXRob3JpemVkIHVzZSBv
# bmx5MTwwOgYDVQQDEzNFbnRydXN0IEV4dGVuZGVkIFZhbGlkYXRpb24gQ29kZSBT
# aWduaW5nIENBIC0gRVZDUzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDCvTcBUALFjaAu6GYnHZUIy25XB1LW0LrF3euJF8ImXC9xK37LNqRREEd4nmoZ
# NOgdYyPieuOhKrZqae5SsMpnwyjY83cwTpCAZJm/6m9nZRIi25xuAw2oUGH4WMSd
# fTrwgSX/8yoS4WvlTZVFysFX9yAtx4EUgbqYLygPSULr/C9rwM298YzqPvw/sXx9
# d7y4YmgyA7Bj8irPXErEQl+bgis4/tlGm0xfY7c0rFT7mcQBI/vJCZTjO59K4oow
# 56ScK63Cb212E4I7GHJpewOYBUpLm9St3OjXvWjuY96yz/c841SAD/sjrLUyXE5A
# PfhMspUyThqkyEbw3weHuJrvAgMBAAGjggEhMIIBHTAOBgNVHQ8BAf8EBAMCAQYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAzBggrBgEF
# BQcBAQQnMCUwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmVudHJ1c3QubmV0MDAG
# A1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwuZW50cnVzdC5uZXQvZzJjYS5jcmww
# OwYDVR0gBDQwMjAwBgRVHSAAMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuZW50
# cnVzdC5uZXQvcnBhMB0GA1UdDgQWBBQqCm8yLCkgIXZqsayMPK+Tjg5rojAfBgNV
# HSMEGDAWgBRqciZ60B7vfec7aVHUbI2fkBJmqzANBgkqhkiG9w0BAQsFAAOCAQEA
# KdkNr2dFXRsJb63MiBD1qi4mF+2Ih6zA+B1TuRAPZTIzazJPXdYdD3h8CVS1WhKH
# X6Q2SwdH0Gdsoipgwl0I3SNgPXkqoBX09XVdIVfA8nFDB6k+YMUZA/l8ub6ARctY
# xthqVO7Or7jUjpA5E3EEXbj8h9UMLM5w7wUcdBAteXZKeFU7SOPId1AdefnWSD/n
# bqvfvZLnJyfAWLO+Q5VvpPzZNgBa+8mM9DieRiaIvILQX30SeuWbL9TEU+XBKdyQ
# +P/h8jqHo+/edtNuajulxlIwHmOrwAlA8cnC8sw41jqy2hVo/IyXdSpYCSziidmE
# CU2X7RYuZTGuuPUtJcF5dDCCBZAwggR4oAMCAQICD3HnAZHCZ4Xw8xAzN3V0njAN
# BgkqhkiG9w0BAQsFADCByDELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVudHJ1c3Qs
# IEluYy4xKDAmBgNVBAsTH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMx
# OTA3BgNVBAsTMChjKSAyMDE1IEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXpl
# ZCB1c2Ugb25seTE8MDoGA1UEAxMzRW50cnVzdCBFeHRlbmRlZCBWYWxpZGF0aW9u
# IENvZGUgU2lnbmluZyBDQSAtIEVWQ1MxMB4XDTIwMTExOTIxNTUwOFoXDTIxMTIx
# MjIxNTUwN1owgdgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVUZXhhczETMBEGA1UE
# BxMKUm91bmQgUm9jazETMBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8
# AgECEwhEZWxhd2FyZTERMA8GA1UEChMIRGVsbCBJbmMxHTAbBgNVBA8TFFByaXZh
# dGUgT3JnYW5pemF0aW9uMR0wGwYDVQQLExRDbGllbnQgUHJvZHVjdCBHcm91cDEQ
# MA4GA1UEBRMHMjE0MTU0MTERMA8GA1UEAxMIRGVsbCBJbmMwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCtsUxaEbdP93k7fH+aROiSPIJ+YewmCSc4fIOo
# 4QeQvzVl2V9i5dS10Vl0pguq30l4EINnHd+8tMgIKwjiKRyuSjzSGv02HhnjIj4N
# ZGAGHAHOl67N8B2Tn2xJs+obpB6S6ZVDlTep30Oaif3wFh0lRPhXwZqmkZo4wPk/
# XTAAr6EvkNsF02BluYDqFYLztXBuTb6TFx/6jXjzN8z2GcYzb2p/LbnVGWeuyyvS
# YkY0z+8QlYezGbsD/5I/aIxi/6hoDhM9t1gmfFu8byeYF0iQv9HN//+yKPpHZ9NX
# cbuFG8yZssRrDMSE+TdDaF0hhywpyDzK2tQL9x9OVaSS8gxbAgMBAAGjggFjMIIB
# XzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQPbg/plOi4U1vRuFqxMH8mepZ6vDAf
# BgNVHSMEGDAWgBQqCm8yLCkgIXZqsayMPK+Tjg5rojBqBggrBgEFBQcBAQReMFww
# IwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmVudHJ1c3QubmV0MDUGCCsGAQUFBzAC
# hilodHRwOi8vYWlhLmVudHJ1c3QubmV0L2V2Y3MxLWNoYWluMjU2LmNlcjAxBgNV
# HR8EKjAoMCagJKAihiBodHRwOi8vY3JsLmVudHJ1c3QubmV0L2V2Y3MxLmNybDAO
# BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwSwYDVR0gBEQwQjA3
# BgpghkgBhvpsCgECMCkwJwYIKwYBBQUHAgEWG2h0dHBzOi8vd3d3LmVudHJ1c3Qu
# bmV0L3JwYTAHBgVngQwBAzANBgkqhkiG9w0BAQsFAAOCAQEAiF7xd3GBxaI9u4RZ
# CEbblLpwzGcmBLvR0fiwgTASbadHYmOTPOYR3PsPsM5tQyLcdei9zser2TsHYNfk
# fmPXXA3C3TtUDzK6jKskniivaTa0DD51rKjiDGCJCaL6PuiaoM7koTmM2vJ+3miP
# rhqZF4dN9oB4/I7qKBCBHAr08VdD7nTP4lkSR54Bgim8I3mS4iEK2EPtRJzKDyqr
# jDlCyRY3EWocFqpnU4qoiMhUwK1CUNvqtTcQOzXhWSjHqPvfQlDINo6GrWadnByT
# yPrcgrfrIwrXkLxj99tvknAB17fFS1Xyku+PkevhkoOpdAWKogXOjrNwuO2etQou
# 8Pl8ODGCEMcwghDDAgEBMIHcMIHIMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNRW50
# cnVzdCwgSW5jLjEoMCYGA1UECxMfU2VlIHd3dy5lbnRydXN0Lm5ldC9sZWdhbC10
# ZXJtczE5MDcGA1UECxMwKGMpIDIwMTUgRW50cnVzdCwgSW5jLiAtIGZvciBhdXRo
# b3JpemVkIHVzZSBvbmx5MTwwOgYDVQQDEzNFbnRydXN0IEV4dGVuZGVkIFZhbGlk
# YXRpb24gQ29kZSBTaWduaW5nIENBIC0gRVZDUzECD3HnAZHCZ4Xw8xAzN3V0njAN
# BglghkgBZQMEAgEFAKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCAEeFZnoEmJhi2jihC/1nsmB3w/x/NULMFLufsxfl9DkTANBgkq
# hkiG9w0BAQEFAASCAQCd4o1OQBLAVD9RnMw0xC+eq2lCHfgJRQ/19BDdWSMeAryi
# mDNT7mPBHQkmgw2l+IWcwSMfob2MRpHzL+EG2TwmAvsNylIXpIhAGDHMV6sh2SmM
# k4L5xsERfArTdRCe1YzquRwbAVnptULWqzSblcXeAFbi4lc+lBlnPx7LYwok1UEe
# YSEV6/qH5SkqyfkguKTIIsfWKugw/95la8c8Z4tm0mIY8b+/CgK6v24ff6tsjD9y
# HiwvpbimmiLa1NblZa8+zpfIEZwEEmgIKCLn0ix66p05J0G2dOjlDWj345nyiy3K
# lIfgQbWcQKNQBgDk7w5BbHwAfOfkX+P27p0E+2XfoYIOPTCCDjkGCisGAQQBgjcD
# AwExgg4pMIIOJQYJKoZIhvcNAQcCoIIOFjCCDhICAQMxDTALBglghkgBZQMEAgEw
# ggEPBgsqhkiG9w0BCRABBKCB/wSB/DCB+QIBAQYLYIZIAYb4RQEHFwMwMTANBglg
# hkgBZQMEAgEFAAQgGXroJnXOXJK7XkSkz6ZkYBHavnaC4VD+ypfwIwZYo7cCFQDY
# LafD61/iOpcrLJC1rQhgs9qZ3BgPMjAyMTA5MDIxMTU1MjVaMAMCAR6ggYakgYMw
# gYAxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEf
# MB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50
# ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBTaWduZXIgLSBHM6CCCoswggU4MIIEIKAD
# AgECAhB7BbHUSWhRRPfJidKcGZ0SMA0GCSqGSIb3DQEBCwUAMIG9MQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWdu
# IFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA4IFZlcmlTaWduLCBJbmMu
# IC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxODA2BgNVBAMTL1ZlcmlTaWduIFVu
# aXZlcnNhbCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE2MDExMjAw
# MDAwMFoXDTMxMDExMTIzNTk1OVowdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5
# bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3
# b3JrMSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIB
# IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1mdWVVPnYxyXRqBoutV87AB
# rTxxrDKPBWuGmicAMpdqTclkFEspu8LZKbku7GOz4c8/C1aQ+GIbfuumB+Lef15t
# QDjUkQbnQXx5HMvLrRu/2JWR8/DubPitljkuf8EnuHg5xYSl7e2vh47Ojcdt6tKY
# tTofHjmdw/SaqPSE4cTRfHHGBim0P+SDDSbDewg+TfkKtzNJ/8o71PWym0vhiJka
# 9cDpMxTW38eA25Hu/rySV3J39M2ozP4J9ZM3vpWIasXc9LFL1M7oCZFftYR5NYp4
# rBkyjyPBMkEbWQ6pPrHM+dYr77fY5NUdbRE6kvaTyZzjSO67Uw7UNpeGeMWhNwID
# AQABo4IBdzCCAXMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# ZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRwczov
# L2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3ltY2Iu
# Y29tL3JwYTAuBggrBgEFBQcBAQQiMCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9zLnN5
# bWNkLmNvbTA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vcy5zeW1jYi5jb20vdW5p
# dmVyc2FsLXJvb3QuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMIMCgGA1UdEQQhMB+k
# HTAbMRkwFwYDVQQDExBUaW1lU3RhbXAtMjA0OC0zMB0GA1UdDgQWBBSvY9bKo06F
# cuCnvEHzKaI4f4B1YjAfBgNVHSMEGDAWgBS2d/ppSEefUxLVwuoHMnYH0ZcHGTAN
# BgkqhkiG9w0BAQsFAAOCAQEAdeqwLdU0GVwyRf4O4dRPpnjBb9fq3dxP86HIgYj3
# p48V5kApreZd9KLZVmSEcTAq3R5hF2YgVgaYGY1dcfL4l7wJ/RyRR8ni6I0D+8yQ
# L9YKbE4z7Na0k8hMkGNIOUAhxN3WbomYPLWYl+ipBrcJyY9TV0GQL+EeTU7cyhB4
# bEJu8LbF+GFcUvVO9muN90p6vvPN/QPX2fYDqA/jU/cKdezGdS6qZoUEmbf4Blfh
# xg726K/a7JsYH6q54zoAv86KlMsB257HOLsPUqvR45QDYApNoP4nbRQy/D+XQOG/
# mYnb5DkUvdrk08PqK1qzlVhVBH3HmuwjA42FKtL/rqlhgTCCBUswggQzoAMCAQIC
# EHvU5a+6zAc/oQEjBCJBTRIwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UEBhMCVVMx
# HTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRl
# YyBUcnVzdCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0
# YW1waW5nIENBMB4XDTE3MTIyMzAwMDAwMFoXDTI5MDMyMjIzNTk1OVowgYAxCzAJ
# BgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UE
# CxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50ZWMgU0hB
# MjU2IFRpbWVTdGFtcGluZyBTaWduZXIgLSBHMzCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAK8Oiqr43L9pe1QXcUcJvY08gfh0FXdnkJz93k4Cnkt29uU2
# PmXVJCBtMPndHYPpPydKM05tForkjUCNIqq+pwsb0ge2PLUaJCj4G3JRPcgJiCYI
# Ovn6QyN1R3AMs19bjwgdckhXZU2vAjxA9/TdMjiTP+UspvNZI8uA3hNN+RDJqgoY
# bFVhV9HxAizEtavybCPSnw0PGWythWJp/U6FwYpSMatb2Ml0UuNXbCK/VX9vygar
# P0q3InZl7Ow28paVgSYs/buYqgE4068lQJsJU/ApV4VYXuqFSEEhh+XetNMmsntA
# U1h5jlIxBk2UA0XEzjwD7LcA8joixbRv5e+wipsCAwEAAaOCAccwggHDMAwGA1Ud
# EwEB/wQCMAAwZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIB
# FhdodHRwczovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczov
# L2Quc3ltY2IuY29tL3JwYTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vdHMtY3Js
# LndzLnN5bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNybDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwdwYIKwYBBQUHAQEEazBpMCoGCCsG
# AQUFBzABhh5odHRwOi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wOwYIKwYBBQUH
# MAKGL2h0dHA6Ly90cy1haWEud3Muc3ltYW50ZWMuY29tL3NoYTI1Ni10c3MtY2Eu
# Y2VyMCgGA1UdEQQhMB+kHTAbMRkwFwYDVQQDExBUaW1lU3RhbXAtMjA0OC02MB0G
# A1UdDgQWBBSlEwGpn4XMG24WHl87Map5NgB7HTAfBgNVHSMEGDAWgBSvY9bKo06F
# cuCnvEHzKaI4f4B1YjANBgkqhkiG9w0BAQsFAAOCAQEARp6v8LiiX6KZSM+oJ0sh
# zbK5pnJwYy/jVSl7OUZO535lBliLvFeKkg0I2BC6NiT6Cnv7O9Niv0qUFeaC24pU
# bf8o/mfPcT/mMwnZolkQ9B5K/mXM3tRr41IpdQBKK6XMy5voqU33tBdZkkHDtz+G
# 5vbAf0Q8RlwXWuOkO9VpJtUhfeGAZ35irLdOLhWa5Zwjr1sR6nGpQfkNeTipoQ3P
# tLHaPpp6xyLFdM3fRwmGxPyRJbIblumFCOjd6nRgbmClVnoNyERY3Ob5SBSe5b/e
# AL13sZgUchQk38cRLB8AP8NLFMZnHMweBqOQX1xUiz7jM1uCD8W3hgJOcZ/pZkU/
# djGCAlowggJWAgEBMIGLMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEo
# MCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQe9Tlr7rM
# Bz+hASMEIkFNEjALBglghkgBZQMEAgGggaQwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMTA5MDIxMTU1MjVaMC8GCSqGSIb3DQEJ
# BDEiBCCm+MBu4xpLZ24QeNskV6rHq9COhVBkrLLz64NWa9TT5zA3BgsqhkiG9w0B
# CRACLzEoMCYwJDAiBCDEdM52AH0COU4NpeTefBTGgPniggE8/vZT7123H99h+DAL
# BgkqhkiG9w0BAQEEggEABfu0R/LfEapG8FyC8gc21uDOztbWR5toLeuYZae9iQW/
# GDhyCjgN+LxlAYGHePcMif5W+tosC6a5dJbhfS5wk0i6T1RGHdN+f4Tt/HDHBYez
# G/RWwpl7bECLtuxUCI/baQGUf6ec9WoPDUuQUl4itevl+HU8dIhzOl6POubRxJCT
# phX9HvDEnssEXNULrw0gxw/lrV8NxfRwk6nyiK3Na9fZ+mLvmtpK0vR0m1tYgUCy
# wVqnHZBwae2Sygz67taITPMvnwwJ5qWrqNjKlkK4bQOatyadGIHYVGPAwxQjIcLv
# iNvU3az11CEv6dD77A7/SvyCLj3B1Ft2dP5fmptJIg==
# SIG # End signature block
