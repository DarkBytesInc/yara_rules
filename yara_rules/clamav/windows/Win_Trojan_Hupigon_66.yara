rule Win_Trojan_Hupigon_66
{
strings:
	$a0 = { 872a18f2f345bc470af7084114b85fcd5804110fbc422bac45ecc5f2f44a5dd18a436f92cac3ea5a3c256c5230c8861e25259e748823502cbaf7f44a27a689f30edee8bcb8f08ce92742023cf40ae408c051d683186d8e0d7a943c0b062dae9c9266b538d28868a7f5b4bc4a670b390279d32cb6 }

condition:
	$a0
}

        