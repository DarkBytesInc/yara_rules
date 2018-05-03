rule Win_Worm_Stration_745
{
strings:
	$a0 = { 8b44240883e800741448751dff742404ff1524100010e8c3feffffeb0cc6050222001050e8a4ffffff33c040c20c00 }

condition:
	$a0
}

        
