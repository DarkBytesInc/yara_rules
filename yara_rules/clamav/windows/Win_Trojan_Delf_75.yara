rule Win_Trojan_Delf_75
{
strings:
	$a0 = { 8d45ec508d55e8a1e0844000e83ef3ffff8b55e858e8b5d3ffff8b45ece8c5d4ffff506a00e865e9fffff7d81bdbf7db84db740c6860ea0000e879e9ffffeb0f6860ea0000e86de9ffffe91affffff33c05a5959648910688a5d40008d45e8ba }

condition:
	$a0
}

        
