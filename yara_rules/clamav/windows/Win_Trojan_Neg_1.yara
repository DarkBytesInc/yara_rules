rule Win_Trojan_Neg_1
{
strings:
	$a0 = { 2000540228008a0100002000540221006002ec0040002000740239006a02ad00aa01 }

condition:
	$a0
}

        
