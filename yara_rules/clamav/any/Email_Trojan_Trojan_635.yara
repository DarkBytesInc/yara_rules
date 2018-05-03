rule Email_Trojan_Trojan_635
{
strings:
	$a0 = { 416c6c20646973636f756e747320696e20796f7572206369747920687474703a }

condition:
	$a0
}

        
