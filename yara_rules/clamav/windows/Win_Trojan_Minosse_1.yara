rule Win_Trojan_Minosse_1
{
strings:
	$a0 = { 2f0087d2fd9049414c444f477200750078007b007e00b44ccd2189db77007a007d0089c089d287c087d2fd9049412a }

condition:
	$a0
}

        
