rule Win_Worm_Stration_743
{
strings:
	$a0 = { 8b44240883e800741448751fff742404ff1524100010e8c3feffffeb0e6681050822001003d8e8a2ffffff33c040c20c00 }

condition:
	$a0
}

        
