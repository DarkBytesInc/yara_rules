rule Win_Trojan_Idele_5
{
strings:
	$a0 = { b826000000b8700800006a30680020400068092040006a00e8070c0000685220 }
	$a1 = { 6279204964656c65 }

condition:
	$a0 and $a1
}

        
