rule Win_Trojan_Lamicho_1
{
strings:
	$a0 = { e8170000008b6424086a00687a224000688a2240006a00e83c0000006467ff36000064678926 }

condition:
	$a0
}

        
