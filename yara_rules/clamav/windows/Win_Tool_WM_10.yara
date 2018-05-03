rule Win_Tool_WM_10
{
strings:
	$a0 = { 010a0055e004000300ffff01030000e4020000100000000103 }

condition:
	$a0
}

        
