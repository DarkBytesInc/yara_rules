rule Unix_Tool_13409_1
{
strings:
	$a0 = { 50682f2f7368682f62696e89e3505389e1b00bcd80 }

condition:
	$a0
}

        
