rule Win_Trojan_Lolo_1
{
strings:
	$a0 = { 612e436f707946696c6520577363726970742e53637269707446756c6c4e616d652c2022413a5c7365782d706963732e766273222c2054727565 }

condition:
	$a0
}

        