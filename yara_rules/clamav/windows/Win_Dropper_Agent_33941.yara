rule Win_Dropper_Agent_33941
{
strings:
	$a0 = { 5983bc24a000000001751be8b00700006800604000e8aa0c00005985c0740750e897020000 }

condition:
	$a0
}

        
