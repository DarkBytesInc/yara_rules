rule Win_Trojan_Plex_1
{
strings:
	$a0 = { 504500004c01??00????????00000000??000000e000????0b01????00????0000??000000000000??????000010000000????000000????0010000000??0000??000000??000000??00??00706c7872 }

condition:
	$a0
}

        