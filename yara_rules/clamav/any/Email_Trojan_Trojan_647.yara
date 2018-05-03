rule Email_Trojan_Trojan_647
{
strings:
	$a0 = { 426f6d62206578706c6f73696f6e20687474703a2f2f }

condition:
	$a0
}

        
