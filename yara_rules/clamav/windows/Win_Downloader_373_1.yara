rule Win_Downloader_373_1
{
strings:
	$a0 = { 686c0700005268c0814000e807000abc8b4df464890d000000008b4dec83c40ce807000e31 }
	$a1 = { 3a2f2f75702e6d650000000064626f642e636f }

condition:
	$a0 and $a1
}

        
