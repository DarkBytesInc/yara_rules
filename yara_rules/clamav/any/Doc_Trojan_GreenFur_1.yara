rule Doc_Trojan_GreenFur_1
{
strings:
	$a0 = { 436172617474657265203d20576f726442617369632e496e7428526e642829202a20283930202d20373529202b20373529 }
	$a1 = { 50617373776f726424203d2050617373776f726424202b204368722843617261747465726529 }

condition:
	$a0 and $a1
}

        