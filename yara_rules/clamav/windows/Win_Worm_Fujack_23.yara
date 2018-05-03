rule Win_Worm_Fujack_23
{
strings:
	$a0 = { c30000007858785f5768426f790000006a006896000000689600000068c80000 }

condition:
	$a0
}

        
