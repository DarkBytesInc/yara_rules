rule Win_Trojan_VGEN_273
{
strings:
	$a0 = { 01b803012e814600000045454875f5e800005d81ed14011e060e1f0e078db6cc018dbec401a5a5a5a5c686790302 }

condition:
	$a0
}

        
