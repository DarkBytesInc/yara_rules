rule Win_Trojan_N_65
{
strings:
	$a0 = { 7405e894ffffff5753ff95dd14400083f80075c053ff95e114400081c40004000061c3608bf2ac0ac075fb8b46fc3d45584500740b3d657865000f85ae0100005268102700006a00ff95e51440008985051540005ae8d1feffff83f8000f847901000093b9282300008b }

condition:
	$a0
}

        