rule Win_Tool_WM_3
{
strings:
	$a0 = { ff01060055b800000300ffff0103000095030000050000000103 }

condition:
	$a0
}

        
