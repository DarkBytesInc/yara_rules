rule Win_Trojan_VB_1618
{
strings:
	$a0 = { 613d000000000000010000002d43303030 }
	$a1 = { 656e750000006376343534350000664f70 }

condition:
	$a0 and $a1
}

        
