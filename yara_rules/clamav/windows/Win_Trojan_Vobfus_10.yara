rule Win_Trojan_Vobfus_10
{
strings:
	$a0 = { 650000000200000074000000020000004d000000020000006f00000002000000640000000200000069000000020000004e00000002000000570000000200000000000000180000000100920001000000000000000000000001020000000000000200000061000000020000006b000000020000007000000002000000630000000200000072000000020000006c }

condition:
	$a0
}

        