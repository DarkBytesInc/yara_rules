rule Win_Trojan_Promark_3
{
strings:
	$a0 = { 666f7220252576[0-14]2a2e6261742920646f2063616c6c20633a5c70726f6d61726b20252576205f }

condition:
	$a0
}

        
