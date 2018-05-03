rule Win_Worm_Stration_527
{
strings:
	$a0 = { 5c0000002e657865000000006c4b434a57484451 }

condition:
	$a0
}

        
