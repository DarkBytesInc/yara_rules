rule Win_Trojan_Mybot_8461
{
strings:
	$a0 = { 1384ebfe80703df5dfe35d38afbbb0dd14df7793aa23e0905f21a47ca52a8bff5ddc436449e6251b324e416a10c14a938877de6282e0031e2af5a74d60a59e2b993f4e571f05bbf64f81eaffaea2261062a74071f1 }

condition:
	$a0
}

        
