rule Win_Trojan_Posa_1
{
strings:
	$a0 = { 433a5c444f43554d457e315c41444d494e497e315c4c4f43414c537e315c54656d705c504f53412e746d702e424154 }

condition:
	$a0
}

        
