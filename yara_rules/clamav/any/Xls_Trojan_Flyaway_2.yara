rule Xls_Trojan_Flyaway_2
{
strings:
	$a0 = { a35c203d20564250726f6a6563743a2053657420a35c203d20a35c2e5642436f6d706f6e656e7473282254686973576f726b62 }
	$a1 = { a368203d20a3642e564250726f6a6563743a2053657420a368203d20a3682e5642436f6d706f6e656e747328a35c292e436f64654d6f }

condition:
	$a0 and $a1
}

        