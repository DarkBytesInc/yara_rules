rule Win_Worm_Delf_2245
{
strings:
	$a0 = { 5c4b617a61615c }
	$a1 = { 5c686f746d61696c5f6861636b65722e657865 }
	$a2 = { 5c61696d5f6861636b2e657865 }

condition:
	$a0 and $a1 and $a2
}

        
