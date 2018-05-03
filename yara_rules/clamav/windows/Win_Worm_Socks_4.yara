rule Win_Worm_Socks_4
{
strings:
	$a0 = { 6a03683c834000e8cafdffff83c408a32c1240005dc3558bece8020000005dc3558bec6a02686c834000e8a7fdffff83c408a304114000 }

condition:
	$a0
}

        
