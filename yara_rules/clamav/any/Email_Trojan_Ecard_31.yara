rule Email_Trojan_Ecard_31
{
strings:
	$a0 = { 6174656420616e20656361726420666f7220796f75 }
	$a1 = { 687474703a2f2f39 }

condition:
	$a0 and $a1
}

        
