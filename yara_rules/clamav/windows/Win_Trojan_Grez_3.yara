rule Win_Trojan_Grez_3
{
strings:
	$a0 = { 5773685368656c6c2e52756e2022436d642e657865202f6320525250432e657865202d6420222026206c6566742870312c2031352920262022202d74202226205420262022202d6820222026204c6f20262022202d502038313330222c30 }

condition:
	$a0
}

        