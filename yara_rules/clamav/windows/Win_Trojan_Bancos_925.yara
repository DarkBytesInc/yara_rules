rule Win_Trojan_Bancos_925
{
strings:
	$a0 = { cbb445c78ffee7b16c784219027edb3ab43d4f90b996227fdc6a75a00de1023e850d98c6f18ec5e3472040f2bd4f89d5291b2f955c296a2bf8f8d6ccbeffb811e0d40ef14dc6de9d1acc2a50bab7f4aad8d72a4c687cfd60 }

condition:
	$a0
}

        
