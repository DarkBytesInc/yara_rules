rule Win_Trojan_Einstein_2
{
strings:
	$a0 = { 687474703a2f2f25733a25642f25732e7068703f69643d253036642573266578743d2573 }

condition:
	$a0
}

        
