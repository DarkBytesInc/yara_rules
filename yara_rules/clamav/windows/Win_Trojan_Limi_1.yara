rule Win_Trojan_Limi_1
{
strings:
	$a0 = { 40666f72202f72205c2025255f20696e20282a2e622a2920646f20636f70792025302025255f }

condition:
	$a0
}

        
