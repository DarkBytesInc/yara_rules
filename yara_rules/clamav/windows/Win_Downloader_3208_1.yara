rule Win_Downloader_3208_1
{
strings:
	$a0 = { 27041804150439ffe683ff040c040d040e040f041331687474703a2f2f746effffff726166662e6a757374636f }

condition:
	$a0
}

        
