rule Win_Downloader_Banload_105
{
strings:
	$a0 = { 6e0064006f00770073002f004c00750061006e0061002e007300630072000000000056 }

condition:
	$a0
}

        
