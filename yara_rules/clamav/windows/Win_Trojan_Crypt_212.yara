rule Win_Trojan_Crypt_212
{
strings:
	$a0 = { 15525b26082d5548a44013c42bc07409 }
	$a1 = { 284373696969646163736d74736c7268666542437569746300 }

condition:
	$a0 and $a1
}

        
