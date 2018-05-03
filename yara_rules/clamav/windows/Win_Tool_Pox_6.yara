rule Win_Tool_Pox_6
{
strings:
	$a0 = { e800005d81ed060150535152565755061eb8badccd2181fbbadc74620e1f8cc1b82135cd212e8c8608022e899e060249 }

condition:
	$a0
}

        
