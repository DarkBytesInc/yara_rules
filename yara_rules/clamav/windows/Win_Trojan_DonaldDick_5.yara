rule Win_Trojan_DonaldDick_5
{
strings:
	$a0 = { c20c000000006d61696c746f3a646f6e616c646469636b406d61696c2e7275000000687474703a2f2f646f6e616c6464 }

condition:
	$a0
}

        
