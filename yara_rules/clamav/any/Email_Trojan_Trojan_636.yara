rule Email_Trojan_Trojan_636
{
strings:
	$a0 = { 416c6c2073616c6573206f6e206f6e65207369746520687474703a }

condition:
	$a0
}

        
