rule Win_Tool_Kerbcrack_1
{
strings:
	$a0 = { 50617373776f726420202020202020202d202573[0-36]6e616d65202020202d202573 }
	$a1 = { 4b657262437261636b }

condition:
	$a0 and $a1
}

        
