rule Win_Trojan_Roller_1
{
strings:
	$a0 = { b82135cd21891e????8c06????b82125ba????cd21071f5b58ea }

condition:
	$a0
}

        
