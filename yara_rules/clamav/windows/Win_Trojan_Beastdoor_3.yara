rule Win_Trojan_Beastdoor_3
{
strings:
	$a0 = { cc70400011022e33040000000010400048000000001040000946756e6374696f6e7a8bc0f070400011022e35040000000010400048000000001040000946756e6374696f6e7a8bc0ff252cf441008bc0ff2524f441008bc0ff251cf441008bc0c705dcd34100070000006a0068dcd34100e8e2ffffff83f8 }

condition:
	$a0
}

        