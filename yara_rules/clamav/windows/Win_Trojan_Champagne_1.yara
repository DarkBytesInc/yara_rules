rule Win_Trojan_Champagne_1
{
strings:
	$a0 = { 59400f84??00000048508b412c3d[0-29]5041565774[0-1]3d415650[0-24]3d462d505274[0-1]3d4e41565774[0-1]3d4e41565474 }

condition:
	$a0
}

        
