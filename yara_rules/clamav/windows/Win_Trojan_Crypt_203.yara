rule Win_Trojan_Crypt_203
{
strings:
	$a0 = { 6633c07403e5192c565303de5b57525a90f7d66888362f718b342483c40456575e81ee3422481f }

condition:
	$a0
}

        
