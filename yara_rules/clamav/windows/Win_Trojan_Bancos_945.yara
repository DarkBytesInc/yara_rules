rule Win_Trojan_Bancos_945
{
strings:
	$a0 = { 6cf3f1140f9f9f1f77f5147f2a3163a0c6806c5795f9d9b3cf19fc30b7959d92df04e2c03ee4a79b20056d14ae605965426d618b8f51a0b2877f344a209827ced953efa2093272461961db9d1dc05570e85a }

condition:
	$a0
}

        