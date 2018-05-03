rule Win_Tool_WM_6
{
strings:
	$a0 = { ff01040055df02000100ffff39030000a02f0000040000002903 }

condition:
	$a0
}

        
