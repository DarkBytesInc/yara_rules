rule Win_Downloader_Delf_432
{
strings:
	$a0 = { ff090000005c637372732e736372000000ffffffff0a0000005c6e657473682e6578650000ffffffff48000000656e5f60 }

condition:
	$a0
}

        
