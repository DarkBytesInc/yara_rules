rule Win_Worm_Stration_718
{
strings:
	$a0 = { ff74240cff74240cff74240c6a00ff152c100010c20c008b44240883e8007414487527ff742404ff1524100010e8c3feffffeb16 }

condition:
	$a0
}

        
