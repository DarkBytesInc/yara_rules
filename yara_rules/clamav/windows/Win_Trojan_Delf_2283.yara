rule Win_Trojan_Delf_2283
{
strings:
	$a0 = { 558becb93f0000006a006a004975f9b8947c0110 }
	$a1 = { 72394f616435665870787264346a6e39 }
	$a2 = { 6555474f592f3870632f59365579536e45 }

condition:
	$a0 and $a1 and $a2
}

        
