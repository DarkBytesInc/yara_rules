rule Win_Trojan_Birgit_48
{
strings:
	$a0 = { b82435cd212e89??????2e8c??????b425[3-4]cd210e07 }

condition:
	$a0
}

        
