rule Win_Trojan_Zapchast_130
{
strings:
	$a0 = { 737461742e706870006b6f6d616e64732e747874004745542000504f5354 }
	$a1 = { 54622e646c6c00626f746b6f6d616e64 }

condition:
	$a0 and $a1
}

        
