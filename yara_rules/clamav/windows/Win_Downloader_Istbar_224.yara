rule Win_Downloader_Istbar_224
{
strings:
	$a0 = { 69643a31303032393437202f6366673a7973625f6c33202f736f66743a3130000000 }

condition:
	$a0
}

        
