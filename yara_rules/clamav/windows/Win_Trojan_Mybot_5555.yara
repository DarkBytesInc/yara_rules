rule Win_Trojan_Mybot_5555
{
strings:
	$a0 = { 0b58ee73616ffbc64521028a989f0bfcdc8fba735b946e09caae4218e730946773512fe88bba33cc5584ec25b9c015a314a1b93930047a55c9619bf2d2dfe317af457a27e73f }

condition:
	$a0
}

        
