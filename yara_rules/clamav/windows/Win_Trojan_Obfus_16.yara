rule Win_Trojan_Obfus_16
{
strings:
	$a0 = { 6681a4??????????????[0-20]6681a4??????????????[0-120]89????????00008b????????00008b????????0000 }

condition:
	$a0
}

        