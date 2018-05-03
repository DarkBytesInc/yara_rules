rule Unix_Tool_13338_1
{
strings:
	$a0 = { 6a3158cd8089c389c16a4658cd8031c050682f2f7368682f62696e545b505389e131d2b00bcd80 }

condition:
	$a0
}

        
