rule Win_Trojan_Win_62
{
strings:
	$a0 = { e8000000005d81ed0520400083fd0074208bfdb9f905000081c731204000668b1f6681f3[0-2]66891f83c70283 }

condition:
	$a0
}

        
