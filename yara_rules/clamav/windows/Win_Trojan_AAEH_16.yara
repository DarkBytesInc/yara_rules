rule Win_Trojan_AAEH_16
{
strings:
	$a0 = { d1ca063d290807519b4cde1d72d1ddf6ce2438cf68ca03cdf0f875df7c76c353eb270581010d80daa4c46a2c64941505 }
	$a1 = { 3837383737434362454a4b49494d4d4d74756279 }

condition:
	$a0 and $a1
}

        
