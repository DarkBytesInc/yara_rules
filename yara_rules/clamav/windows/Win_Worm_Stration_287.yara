rule Win_Worm_Stration_287
{
strings:
	$a0 = { 8b44240883e8007414487520ff742404ff1524100010e8c3feffffeb0f8105002200104a310000e8a1ffffff33c040c20c00 }

condition:
	$a0
}

        
