rule Win_Worm_Autorun_390
{
strings:
	$a0 = { 6801504000e801000000c3c319775e76a3320813f8bb213868876ae47baba2d2 }

condition:
	$a0
}

        
