rule Win_Trojan_Delf_2243
{
strings:
	$a0 = { 558becb91e0000006a006a004975f9b88c6e4700e8160057b033c05568b177470064ff306489208d }

condition:
	$a0
}

        
