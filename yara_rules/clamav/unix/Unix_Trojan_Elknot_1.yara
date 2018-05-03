rule Unix_Trojan_Elknot_1
{
strings:
	$a0 = { 83c40c8d55e483ec0468[2]12088d45e85052 }
	$a1 = { 66616b652e636667 }

condition:
	$a0 and $a1
}

        
