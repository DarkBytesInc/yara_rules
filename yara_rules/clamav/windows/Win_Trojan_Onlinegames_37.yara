rule Win_Trojan_Onlinegames_37
{
strings:
	$a0 = { beb0114000ad50ff7634eb7c48010f010b014c6f61644c6962726172794100001810000010000000003000000000400000100000000200000400000000003900040000000000000000100100000200000000000002000000000010000010000000001000 }

condition:
	$a0
}

        