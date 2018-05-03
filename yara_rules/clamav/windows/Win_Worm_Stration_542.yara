rule Win_Worm_Stration_542
{
strings:
	$a0 = { b3000000123e3f25343f257c1d343f3625396b51000000006057574a57250000744f4a4f }

condition:
	$a0
}

        
