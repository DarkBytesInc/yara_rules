rule Email_Trojan_Trojan_697
{
strings:
	$a0 = { 53686f772064652073656e7375616c6964616465 }
	$a1 = { 436c6971756520652056656a61 }

condition:
	$a0 and $a1
}

        
