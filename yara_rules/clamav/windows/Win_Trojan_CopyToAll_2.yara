rule Win_Trojan_CopyToAll_2
{
strings:
	$a0 = { 666f72202f72205c2025257820696e2028633a5c6d79646f63757e315c2a2e2a2c20633a5c2a2e2a2c202a2e2a2c202577696e646972255c2a2e2a2c202577696e626f6f74646972255c2a2e2a2920646f20636f7079202525782b2530202525780d }

condition:
	$a0
}

        