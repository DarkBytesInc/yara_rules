rule Win_Trojan_Agent_35171
{
strings:
	$a0 = { 9ce8000000005ff848535a488bdf81efc1100100c1cafe573cf848f981c33d000000464833d0466800000000 }

condition:
	$a0
}

        
