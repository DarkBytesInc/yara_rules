rule Win_Trojan_Delf_1528
{
strings:
	$a0 = { b810554000e81ef1ffffb8bc404000b9070000008b1500104000e8adf4ffffb8a0404000b9070000008b1500104000e898f4ffff }

condition:
	$a0
}

        
