rule Unix_Tool_13413_1
{
strings:
	$a0 = { 31c031db50682f2f7368682f62696e89e3505389e131d2b00b0f34 }

condition:
	$a0
}

        
