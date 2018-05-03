rule Win_Tool_VB_73675
{
strings:
	$a0 = { 4d61696c2033202859474d29 }
	$a1 = { 652d6d61696c20626f6d626572 }

condition:
	$a0 and $a1
}

        
