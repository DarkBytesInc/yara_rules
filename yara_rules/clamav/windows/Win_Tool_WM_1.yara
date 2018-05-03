rule Win_Tool_WM_1
{
strings:
	$a0 = { 0b00550005000300fffffe6300004f020000040000000e64 }

condition:
	$a0
}

        
