rule Win_Trojan_Small_3234
{
strings:
	$a0 = { ed7ae228e08f090d3ca7410620074e3504674d2d046f7e26e006c51ba094410d4990190d44fa70762c2bc975342bdd39326d7053e070c5522471c5924a07522d047f2fe93071c5e7f5ead528e08b85f864a3 }

condition:
	$a0
}

        