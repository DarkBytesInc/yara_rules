rule Win_Trojan_Vobfus_70354
{
strings:
	$a0 = { 7300700000000600000073006500610000000400000072006300000000000c0000006800650072002e006f0072000000000002000000670000000600000070006c0061000000020000007900000004000000310033000000000002000000350000000400000032002e0000000000080000006e00730031002e0000000000040000006c00610000000000040000007900650000000000040000007200310000000000 }

condition:
	$a0
}

        