rule Win_Trojan_Small_4319
{
strings:
	$a0 = { e8??000000e8??000000[0-255]f7d3ffc381e800440000f7d0ffc053 }

condition:
	$a0
}

        
