rule Win_Trojan_IRCBot_78
{
strings:
	$a0 = { 46333278763900383a9d7859f4956cd831ce55ccfd17dfd1a322c2296e7c6dc38d01b3d6ea0ad04f7d474ecdf99cdf2c9b6834dced450dfefbf64023692ff6f4b835049a7512733a6770f2bab4d34ace90c223808c5c25e2ccb381ad0146dd4d32d777f74308de9d9b59d50286839d849d1b4cddf1e0791fe8eed0f2164a806236228e143c547738cb6716b867d890b58a3b0811da86 }

condition:
	$a0
}

        