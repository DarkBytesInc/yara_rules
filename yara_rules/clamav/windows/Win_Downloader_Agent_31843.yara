rule Win_Downloader_Agent_31843
{
strings:
	$a0 = { a2c0228ddc1d4118afb1682f372fcd36553b7fb3780dfb559d7a25fd91c733e640ebd9484259e474f4e95239205b5eb03652e2218d4d7277e7ab09a385a733abd9722cdbb79af2730f12c6 }

condition:
	$a0
}

        
