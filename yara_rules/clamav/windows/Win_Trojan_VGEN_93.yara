rule Win_Trojan_VGEN_93
{
strings:
	$a0 = { 03fc8bf283c642b90300bf0001f3a48bf2b430c606190401e833003c007503e9940206b42fc606190401e82100 }

condition:
	$a0
}

        
