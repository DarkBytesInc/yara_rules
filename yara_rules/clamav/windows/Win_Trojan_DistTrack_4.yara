rule Win_Trojan_DistTrack_4
{
strings:
	$a0 = { 6d00790069006d00610067006500310032003700360037[0-10]50004b0043005300310032 }

condition:
	$a0
}

        