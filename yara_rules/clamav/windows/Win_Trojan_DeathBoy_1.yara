rule Win_Trojan_DeathBoy_1
{
strings:
	$a0 = { 0b0050754e6b496e486541641aeb4ec300545afaa4740407010d009f00880201001e0522001e054d000000830026bd }

condition:
	$a0
}

        
