rule Win_Trojan_Peed_117
{
strings:
	$a0 = { e90f00000039d80f8e01000000c358e97a000000babb??400087??688000000068810000006a006a }

condition:
	$a0
}

        
