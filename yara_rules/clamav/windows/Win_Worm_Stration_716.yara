rule Win_Worm_Stration_716
{
strings:
	$a0 = { ff74240cff74240cff74240c6a00ff152c100010c20c008b44240883e800741448752fff742404ff1524100010e8c3feffffeb1e }

condition:
	$a0
}

        
