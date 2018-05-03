rule Doc_Trojan_Cobra_8
{
strings:
	$a0 = { 4f6e204572726f7220526573756d65204e657874 }
	$a1 = { 496620[0-50]284e6f7729203d20 }
	$a2 = { 5368656c6c2022(64|44)656c74726565202f7920(43|63)3a5c22 }

condition:
	$a0 and $a1 and $a2
}

        
