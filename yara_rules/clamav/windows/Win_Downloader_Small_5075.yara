rule Win_Downloader_Small_5075
{
strings:
	$a0 = { 1000000000fa3a70376c469fb8304578f7ebe634e54d72a102318320526567a3533630764e000000004ce14a5ca9c07b61393735fc386430ba2d793a6266b831fbe7e939c534f3fe240000000073633d43669c38627c7f6c7dd1b57768616c685941e7a7c27665af8e677570d100004c0b496e73f8e3839420436f6d7ed6daf3d41fa0213800000000548595 }

condition:
	$a0
}

        