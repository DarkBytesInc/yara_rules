rule Email_Trojan_Ecard_35
{
strings:
	$a0 = { 6561746564206120[0-16]6361726420666f7220796f75 }
	$a1 = { 687474703a2f2f35 }

condition:
	$a0 and $a1
}

        
