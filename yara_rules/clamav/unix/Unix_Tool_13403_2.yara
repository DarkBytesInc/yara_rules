rule Unix_Tool_13403_2
{
strings:
	$a0 = { 31c9565b6a3f58cd804180f90375f5 }

condition:
	$a0
}

        
