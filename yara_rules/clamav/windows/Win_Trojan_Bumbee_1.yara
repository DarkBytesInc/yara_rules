rule Win_Trojan_Bumbee_1
{
strings:
	$a0 = { 5a756c837d18407466837d1a007560817d1265737459c745126573518b4508b110f6e1598b }

condition:
	$a0
}

        
