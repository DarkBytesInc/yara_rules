rule Win_Trojan_Patched_141
{
strings:
	$a0 = { e808dffcff }
	$a1 = { 0160b20000000000000000000000000000ec1400019c60e830de0000000000000000000000000000 }

condition:
	$a0 and $a1
}

        
