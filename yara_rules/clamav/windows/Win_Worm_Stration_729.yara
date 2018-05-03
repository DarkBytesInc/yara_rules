rule Win_Worm_Stration_729
{
strings:
	$a0 = { 8b44240883e8007414487516ff742404ff1524100010e8a1feffffeb05e889ffffff33c040c20c00 }

condition:
	$a0
}

        
