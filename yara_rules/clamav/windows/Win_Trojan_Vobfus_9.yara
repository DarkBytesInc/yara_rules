rule Win_Trojan_Vobfus_9
{
strings:
	$a0 = { 69006e00000000000400000064006f00000000000400000073005c00000000000800000064006f0077007300000000000400000055007000000000000400000064006100000000000400000074006500000000000600000041007500740000000600000055007000640000000e00000077006b00330052003600730054000000 }

condition:
	$a0
}

        