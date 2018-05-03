rule Win_Tool_WM_2
{
strings:
	$a0 = { ff01060055a504000300ffff01030000e2000000060000000103 }

condition:
	$a0
}

        
