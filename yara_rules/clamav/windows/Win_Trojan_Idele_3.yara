rule Win_Trojan_Idele_3
{
strings:
	$a0 = { b825000000b80f0800006a30680020400068092040006a00e8a30b0000685220 }
	$a1 = { 6279204964656c65 }

condition:
	$a0 and $a1
}

        
