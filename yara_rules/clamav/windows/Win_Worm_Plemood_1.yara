rule Win_Worm_Plemood_1
{
strings:
	$a0 = { 6a00680030400068033040006a00e802000000c3 }

condition:
	$a0
}

        
