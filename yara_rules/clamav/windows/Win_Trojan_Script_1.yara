rule Win_Trojan_Script_1
{
strings:
	$a0 = { 0d001e1bf420425242b220766972757320627920457853747265730d002811f420536f7572636520636f64650d003226f420 }

condition:
	$a0
}

        