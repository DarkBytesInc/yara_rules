rule Win_Trojan_Supova_1
{
strings:
	$a0 = { 504500004c0104005fb9e03400000000000000000000000053757065726e6f76610000004c61756e6368657200000000 }

condition:
	$a0
}

        