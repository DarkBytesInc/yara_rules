rule Win_Tool_WM_5
{
strings:
	$a0 = { 0b0055c001000300ffff010300004f0200000f0000000103 }

condition:
	$a0
}

        
