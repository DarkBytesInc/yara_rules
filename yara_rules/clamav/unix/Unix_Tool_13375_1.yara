rule Unix_Tool_13375_1
{
strings:
	$a0 = { 31c050682f2f7368682f62696e89e3505389e131d2b00bcd80 }

condition:
	$a0
}

        
