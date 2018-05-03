rule Php_Trojan_Envl_1
{
strings:
	$a0 = { 7368656c6c6e616d65 }
	$a1 = { 656e766c70617373 }
	$a2 = { 687474703a2f2f7777772e376a796577752e636e2f }

condition:
	$a0 and $a1 and $a2
}

        
