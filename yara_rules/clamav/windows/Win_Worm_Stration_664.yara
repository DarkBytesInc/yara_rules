rule Win_Worm_Stration_664
{
strings:
	$a0 = { 7b6a427a03774e0f0005ca24073f3edf7edbfe2f320b4a0096a1d8a57489b1b0a1bce047766165ffffb7ff706157616965746c6b0b450400b28d9893ae }

condition:
	$a0
}

        
