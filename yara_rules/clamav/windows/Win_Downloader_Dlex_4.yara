rule Win_Downloader_Dlex_4
{
strings:
	$a0 = { 7068746d6c0d0a6909 }
	$a1 = { 6d652e636f6d092f616d78700d0a7309310d0a64097472616365726f757465096e65772e642d65787472 }

condition:
	$a0 and $a1
}

        
