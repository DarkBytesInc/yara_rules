rule Win_Trojan_Philis_110
{
strings:
	$a0 = { 562bf35e6050b82f81000058e80000000051596081ee7b1d000081c31156000061575333f8 }

condition:
	$a0
}

        
