rule Win_Trojan_Delf_2349
{
strings:
	$a0 = { 330036003600390039002e0062006100740000000000b0040200ffffffff }
	$a1 = { 5dc300b0040200ffffffff07000000490045004600720061006d006500000089500cc353568bf28bd88d4310 }

condition:
	$a0 and $a1
}

        