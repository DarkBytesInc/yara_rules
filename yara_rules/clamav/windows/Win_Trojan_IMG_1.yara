rule Win_Trojan_IMG_1
{
strings:
	$a0 = { 696f6e00000067676e0022257322202d7500494e53002477696e646f77735c736f756e646775692e6578650000002474656d705c257300000000001f1c1f1e1f1e1f }

condition:
	$a0
}

        