rule Win_Worm_Stration_748
{
strings:
	$a0 = { ff74240cff74240cff74240c6a00ff1528100010c20c008b44240883e800740a48750ce80dfeffffeb05e8b5ffffff33c040c20c00 }

condition:
	$a0
}

        
