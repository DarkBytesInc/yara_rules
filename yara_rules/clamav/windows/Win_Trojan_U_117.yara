rule Win_Trojan_U_117
{
strings:
	$a0 = { 57565381ec1c01000066c744240a2e00e8000000005889c781c754800408c7442404 }

condition:
	$a0
}

        
