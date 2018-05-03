rule Osx_Trojan_Okaz_1
{
strings:
	$a0 = { 69645f636861747a756d }
	$a1 = { 50686f746f73686f70204943432070726f66696c65 }

condition:
	$a0 and $a1
}

        
