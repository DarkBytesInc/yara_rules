rule Win_Trojan_U_55
{
strings:
	$a0 = { 6f722076696320696e202a0a646f0a20637020243020247669630a646f6e65 }

condition:
	$a0
}

        
