rule Xls_Trojan_Sugar_1
{
strings:
	$a0 = { 63203d2057726974655072697661746550726f66696c65537472696e67412822323941222c20224d757368726f6f6d222c2022363636222c2022633a5c6c6f2e696478 }

condition:
	$a0
}

        