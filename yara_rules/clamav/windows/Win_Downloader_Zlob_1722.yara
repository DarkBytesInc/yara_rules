rule Win_Downloader_Zlob_1722
{
strings:
	$a0 = { 4761eaa92a7f8b467b5e80e484e6c56b7b7d4dc430d0badbe8cb7531dca7d0803e168e25c0a29d1ce0aae8839d6e6320535fd4675f633819fc5fddecee65b56c850777883dfad119c88259afb7e865ed2d4fc716b7efd869bb27 }

condition:
	$a0
}

        
