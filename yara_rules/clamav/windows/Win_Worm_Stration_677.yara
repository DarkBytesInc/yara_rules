rule Win_Worm_Stration_677
{
strings:
	$a0 = { 6489250000000083ec505356578965e801006c6e02e8010076ec59a3d8e84000e801006efc85c075086a01 }

condition:
	$a0
}

        
