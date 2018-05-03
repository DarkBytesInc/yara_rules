rule Win_Worm_Socks_15
{
strings:
	$a0 = { 558bec6a0668e0844000e80afeffff5959a3301140005dc3558bece8020000005dc3558bec6a056818854000e8e8fdffff5959a3081040005dc3 }

condition:
	$a0
}

        
