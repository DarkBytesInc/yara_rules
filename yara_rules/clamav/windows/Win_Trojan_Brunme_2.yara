rule Win_Trojan_Brunme_2
{
strings:
	$a0 = { bcbb0a0054e8006c0b00e09bf644242c0174050fb75c24308bc33e2f5a17445bc3a8fcfcfc58a4a09c98ecfcfcfc94908c539c00200b56bed055833e00753a68440600103bc16a00f78bc885c9750533c05e4170819ca1cc8901890d0000a06333d28bc203c08d44c1048b1e891889064283fa74715d006475ec8b068b108916908970add78640048bf22313 }

condition:
	$a0
}

        