rule Win_Trojan_Bancos_1819
{
strings:
	$a0 = { f107fd47df4a471ed9a9b13b7ba9bbe924992473ee75c70200c058c4659cc83eb4fd63354c03c5f331feb03470963bacb97c802e1c9380c2f3ec9ded588bc5b4838e38289052 }

condition:
	$a0
}

        
