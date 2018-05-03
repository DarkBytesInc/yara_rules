rule Email_Trojan_Trojan_642
{
strings:
	$a0 = { 44696420796f75207365652069743f20687474703a2f2f }

condition:
	$a0
}

        
