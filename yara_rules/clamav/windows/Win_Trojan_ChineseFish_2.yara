rule Win_Trojan_ChineseFish_2
{
strings:
	$a0 = { 349049424d20204856330002020100027000d002fd020009000200000000000000000000002988693107566972757348756e746572fa33c08ed0bc007c1607bb780036c5371e561653bf2b7cb90b00fcac26803d007400268a058a05aa8ac4061ffb7200a0107c98fab8c0078ed8bf0000be0000a1 }

condition:
	$a0
}

        