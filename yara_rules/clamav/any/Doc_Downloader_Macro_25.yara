rule Doc_Downloader_Macro_25
{
strings:
	$a0 = { 4e616d653d2250726f6a65637422 }
	$a1 = { 48656c70436f6e7465787449443d223022 }

condition:
	$a0 and $a1
}

        
