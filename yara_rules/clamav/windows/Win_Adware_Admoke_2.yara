rule Win_Adware_Admoke_2
{
strings:
	$a0 = { 312e4d6f4b6541442e636f6d2f6e65742f000000558bec33c055685ed9410064ff30648920b878f84100b906000000 }

condition:
	$a0
}

        
