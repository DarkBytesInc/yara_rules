rule Win_Trojan_Pronny_2
{
strings:
	$a0 = { 6a31326b6e353433323500696e66656c696369746f75736e657373000001000600dc5240 }

condition:
	$a0
}

        
