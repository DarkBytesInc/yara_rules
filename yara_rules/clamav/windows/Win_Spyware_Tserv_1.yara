rule Win_Spyware_Tserv_1
{
strings:
	$a0 = { 6563000000000000000000000000000000009602c43500000000a6ec000001000000030000000300000088ec000094ec0000a0ec0000f0100000e011000040120000b0ec0000bdec0000ccec000000000100020054534552562e646c6c00496e7374616c6c486f6f6b7300556e696e7374616c6c486f6f6b730057726974654c6f674578000000 }

condition:
	$a0
}

        