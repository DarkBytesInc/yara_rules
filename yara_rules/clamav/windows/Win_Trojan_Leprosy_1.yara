rule Win_Trojan_Leprosy_1
{
strings:
	$a0 = { 2e455845002a2e434f4d002e2e000d0a50726f6772616d20746f6f2062696720746f2066697420 }

condition:
	$a0
}

        
