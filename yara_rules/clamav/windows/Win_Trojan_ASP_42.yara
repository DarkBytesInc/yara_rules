rule Win_Trojan_ASP_42
{
strings:
	$a0 = { 63616c6c64656c286126786469722e6e616d6526225c2229[0-22]64656c657465286129 }

condition:
	$a0
}

        
