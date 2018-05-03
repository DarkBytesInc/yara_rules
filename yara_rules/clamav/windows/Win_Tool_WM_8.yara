rule Win_Tool_WM_8
{
strings:
	$a0 = { 550000000000ffff0000000059080000070000000803 }

condition:
	$a0
}

        
