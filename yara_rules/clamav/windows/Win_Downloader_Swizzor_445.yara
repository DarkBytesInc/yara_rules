rule Win_Downloader_Swizzor_445
{
strings:
	$a0 = { 1cfeb5ec3a5f07fae6203d38f402fd4f7a83d1604740778a9acb98d2d7365593939b253a6475b0ec30b47dd16652d59bbf1017b016ff15c2657ed41eb6b9f31eb05e4af575166eb6b570f8e93b3e0da2b5fee3415cb579d55b3a }

condition:
	$a0
}

        
