rule Win_Trojan_VKit_5
{
strings:
	$a0 = { 12079a3203c2069a0d0060065589e5b800029acd02120781ec00029a2e00c2069a7102c2069a6b0e1207b00750 }

condition:
	$a0
}

        
