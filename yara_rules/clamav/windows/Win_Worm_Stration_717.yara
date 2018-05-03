rule Win_Worm_Stration_717
{
strings:
	$a0 = { faffffc3ff74240cff74240cff74240c6a00ff152c100010c20c008b44240883e800 }

condition:
	$a0
}

        
