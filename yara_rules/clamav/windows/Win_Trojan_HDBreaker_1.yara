rule Win_Trojan_HDBreaker_1
{
strings:
	$a0 = { 44427265616b65725c536563746f725c534543544f522e70646200ff1000ff01003000b8010000b801340056535f56455253494f4e5f494e464f00bd04effe0000010000000400b603000000000400b60300003f0000000000000001 }

condition:
	$a0
}

        