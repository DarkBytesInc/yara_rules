rule Win_Downloader_12942_1
{
strings:
	$a0 = { b84d1640008bc083f02083f0208bf883c72d558bec53b8cc224000be171740002bf78bce51578bd8508bc0e804010000 }

condition:
	$a0
}

        
