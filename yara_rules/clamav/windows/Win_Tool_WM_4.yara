rule Win_Tool_WM_4
{
strings:
	$a0 = { ff010a0055f506000300ffff01030000e7020000020000000103 }

condition:
	$a0
}

        
