rule Win_Trojan_W_91
{
strings:
	$a0 = { 010000bf67214000803f2e740347ebf847c707434f4d006867214000689f204000e8fb000000 }

condition:
	$a0
}

        
