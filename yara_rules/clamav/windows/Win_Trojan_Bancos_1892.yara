rule Win_Trojan_Bancos_1892
{
strings:
	$a0 = { b8cc1b12ebf1e0e1c42259b834f2851751e97cf2cc68198f0f27532c58a81b4ebf481e1750c8a8a32e8414686187fcd2db5b3edc8a1b7b1b9700e330bbb3e4508f8839a0a927 }

condition:
	$a0
}

        
