rule Win_Worm_Fesber_1
{
strings:
	$a0 = { 532d4d592d484557524f00b201a18c464000e860ddffffe80fffffffc38bc05383c4e0e8b3d5ffff66bb14006a006a008d44240850b9cc51400033d233c0e884e6ffff66ffcb75e4eb0a8d44240450e8d7f2ffff6a006a006a008d }

condition:
	$a0
}

        
