rule Win_Trojan_Bifrose_721
{
strings:
	$a0 = { 5500ec83ec4400ff15181040008bf08a063c2275148a46014684c074043c2275f4803e22750d46eb0a3c207e0646803e207ffa8a0684c074043c207ee98365e8008d45bc50ff1514104000e85d0000006830104000002c104000e834000000f645e80159 }

condition:
	$a0
}

        