rule Win_Trojan_Delf_1676
{
strings:
	$a0 = { 5461736b626172437265617465640000832d3890460001c3558bec83c4f0b874e84500e8747afaffa1941e }

condition:
	$a0
}

        
