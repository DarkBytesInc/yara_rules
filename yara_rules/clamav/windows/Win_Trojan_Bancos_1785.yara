rule Win_Trojan_Bancos_1785
{
strings:
	$a0 = { 803800c909932885b417d5d4d2154325dafeaad5f463abd4a048c3d5bf0449e66741cdb4f627fc7132cc81929c8c7c2f23d0e6dc94a745e0fb7e236ea801e0d4d657884ae157 }

condition:
	$a0
}

        
