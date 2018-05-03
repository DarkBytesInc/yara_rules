rule Win_Worm_SysClock_1
{
strings:
	$a0 = { 68d8c340008d4df88bc7ba13000000e8c9f9ffffff75f88d432cba03000000e8d974ffff8d4dfc8bc6ba10000000e8aaf9ffffff75fc68e8c340008d4df88bc7ba13000000e893f9ffff }

condition:
	$a0
}

        
