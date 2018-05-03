rule Win_Worm_Stration_558
{
strings:
	$a0 = { 6d6a6d6a600000001a6c710031000000fccbcbd6cbb9000048737673726a733d786f6f72 }

condition:
	$a0
}

        
