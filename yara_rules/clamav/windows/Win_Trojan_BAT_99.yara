rule Win_Trojan_BAT_99
{
strings:
	$a0 = { 6d735c737461727475705c6b616e6761726f6f2e626174 }
	$a1 = { 726420633a5c77696e646f77735c726570616972 }

condition:
	$a0 and $a1
}

        
