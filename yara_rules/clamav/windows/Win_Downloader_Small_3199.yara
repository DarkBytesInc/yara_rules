rule Win_Downloader_Small_3199
{
strings:
	$a0 = { 2f77002e31363363762e636f6d2f7669702f292c85cd7000372192219232332c9221923435 }

condition:
	$a0
}

        
