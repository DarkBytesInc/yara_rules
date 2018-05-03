rule Html_Trojan_Wuke_1
{
strings:
	$a0 = { 3c696672616d65207372633d687474703a2f2f77616e676d }

condition:
	$a0
}

        
