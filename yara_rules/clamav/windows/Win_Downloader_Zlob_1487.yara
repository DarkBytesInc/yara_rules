rule Win_Downloader_Zlob_1487
{
strings:
	$a0 = { b2856e57ed78617816bb405d1b7fb7d978230d56f4f384dac4ea55e0b035b99851edf013a7aad011831bf6019d69b59add9a219e3a68c4abe95f035918f2cc0b3d358d69547b738f65ae50c392997fdaa67af7fe }

condition:
	$a0
}

        
