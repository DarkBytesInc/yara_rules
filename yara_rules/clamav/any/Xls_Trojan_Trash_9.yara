rule Xls_Trojan_Trash_9
{
strings:
	$a0 = { 4170706c69636174696f6e2e576f726b626f6f6b73282251756172616e74696e652e584c5322292e4d6f64756c6573282251756172616e74696e6522292e436f70792061667465723a3d4170706c69636174696f6e2e576f726b626f6f6b732822504552534f4e414c2e584c4c22292e4d6f64756c6573283129 }

condition:
	$a0
}

        