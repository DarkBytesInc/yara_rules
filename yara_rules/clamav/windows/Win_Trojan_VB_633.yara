rule Win_Trojan_VB_633
{
strings:
	$a0 = { 67697374726f00000000626f6f745f696e6900000000000000006d65726c696e5f7075746561646f72003800c80000000b000000000034000200440003004800020058000200680002007800020088000200980001009c000200b8000300b8000300233dfb }

condition:
	$a0
}

        