rule Html_Trojan_VBCrack_1
{
strings:
	$a0 = { 466c6173682e657865[0-33]31362e3837392e363136206279746573 }
	$a1 = { 43007200610063006b }

condition:
	$a0 and $a1
}

        
