rule Win_Trojan_Yaz_1
{
strings:
	$a0 = { 64a1000000008b4004803855740340ebf883c0038b00c1e010b90000????01c189cbb9????000068????????8b142481c24523f10001da83c40489d789d652ad2d }

condition:
	$a0
}

        
