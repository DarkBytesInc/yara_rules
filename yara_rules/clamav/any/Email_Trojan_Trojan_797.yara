rule Email_Trojan_Trojan_797
{
strings:
	$a0 = { 61732070726d6f736564206368616e67656c6f67206973203d0a61747461636865642c2c }

condition:
	$a0
}

        
