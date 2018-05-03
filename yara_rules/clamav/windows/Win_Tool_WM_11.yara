rule Win_Tool_WM_11
{
strings:
	$a0 = { 040055df02000100ffff29030000c3300000040000002903 }

condition:
	$a0
}

        
