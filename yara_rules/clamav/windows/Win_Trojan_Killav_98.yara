rule Win_Trojan_Killav_98
{
strings:
	$a0 = { 0a0000006b61767376632e6578650000ffffffff0a0000005650547261792e6578650000ffffffff0a0000005241564d4f4e2e6578650000ffffffff0a0000004b61765046572e6578 }

condition:
	$a0
}

        