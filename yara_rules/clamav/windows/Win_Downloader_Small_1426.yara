rule Win_Downloader_Small_1426
{
strings:
	$a0 = { 504936353334433634412d5a3435bdfdedcd342d452d4246102d303833433209345336ffffffaf4c27687474703a2f2f }

condition:
	$a0
}

        
