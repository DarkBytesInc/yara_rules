rule Win_Trojan_Fret_1
{
strings:
	$a0 = { 4069662027255f46726574313032253d3d2720676f746f205f46726574313032 }

condition:
	$a0
}

        
