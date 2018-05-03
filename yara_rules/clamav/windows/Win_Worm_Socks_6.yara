rule Win_Worm_Socks_6
{
strings:
	$a0 = { 6a056878834000e8cafdffff83c408a3301240005dc3558bece8020000005dc3558bec6a0668a8834000e8a7fdffff83c408a3081140005dc3 }

condition:
	$a0
}

        
