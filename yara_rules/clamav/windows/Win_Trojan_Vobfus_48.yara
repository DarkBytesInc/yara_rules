rule Win_Trojan_Vobfus_48
{
strings:
	$a0 = { 3900330053000000100000004700650074004d006f00640075006c00000000000400000065004600000000000600000065004e0061000000060000006800630046000000 }

condition:
	$a0
}

        