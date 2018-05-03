rule Win_Worm_Anap_1
{
strings:
	$a0 = { 77f5be7e31400025ff00000033d2b104f6e103f08b365657bffc224000 }

condition:
	$a0
}

        
