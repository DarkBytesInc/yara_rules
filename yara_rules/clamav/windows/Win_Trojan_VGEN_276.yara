rule Win_Trojan_VGEN_276
{
strings:
	$a0 = { 030150b452cd21268b57febf40033e8913bf40033e8e03268b160300423e011326803e00005a75e9068cc22603 }

condition:
	$a0
}

        
