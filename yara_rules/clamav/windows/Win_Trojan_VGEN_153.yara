rule Win_Trojan_VGEN_153
{
strings:
	$a0 = { 30cd213c041bf6b452cd2126c51f8b40153d70007511803f00740c918b7813c740136b018c4815c5581983fbff75df }

condition:
	$a0
}

        
