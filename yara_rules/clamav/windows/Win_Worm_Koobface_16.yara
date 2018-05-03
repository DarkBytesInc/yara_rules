rule Win_Worm_Koobface_16
{
strings:
	$a0 = { 64656c2022257322 }
	$a1 = { 504f5354 }
	$a2 = { 2f6c6f67732e706870 }
	$a3 = { 5c6d73747265372e657865 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
