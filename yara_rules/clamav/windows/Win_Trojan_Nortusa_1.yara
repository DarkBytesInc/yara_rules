rule Win_Trojan_Nortusa_1
{
strings:
	$a0 = { b86cba51005064ff35000000006489250000000033c089085045436f6d706163743200135fac }

condition:
	$a0
}

        
