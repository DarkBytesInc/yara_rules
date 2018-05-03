rule Unix_Tool_13277_1
{
strings:
	$a0 = { 31c050682f2f7368682f746d7089e3505389e250525350b03bcd8031c0405050cd80 }

condition:
	$a0
}

        
