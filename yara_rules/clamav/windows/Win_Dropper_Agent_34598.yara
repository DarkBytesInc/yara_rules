rule Win_Dropper_Agent_34598
{
strings:
	$a0 = { 33dbff350030400053e84a010000a31c30400054535368161140005353e81e01000068c8000000e83e010000ebf43a3a3ac2aaaeaaaac28a9aeaaac2ae9aeaaa42adabaaaac2a39aeaaac28a9aeaaa4282abaaaac2aaaeaaaac28a9eeaaaf94244aaaaaa }

condition:
	$a0
}

        
