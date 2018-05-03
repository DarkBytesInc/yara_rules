rule Win_Worm_Stration_708
{
strings:
	$a0 = { ff74240cff74240cff74240c6a00ff152c100010c20c00 }

condition:
	$a0
}

        
