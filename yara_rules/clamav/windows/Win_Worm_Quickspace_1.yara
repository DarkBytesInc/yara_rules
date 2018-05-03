rule Win_Worm_Quickspace_1
{
strings:
	$a0 = { 3c656d626564207372633d222b6c6c6c2b22207069616632697573776f2e6d6f76202f3e }

condition:
	$a0
}

        
