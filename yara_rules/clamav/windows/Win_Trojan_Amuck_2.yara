rule Win_Trojan_Amuck_2
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21b42acd21 }

condition:
	$a0
}

        
