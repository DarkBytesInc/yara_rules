rule Unix_Tool_13362_1
{
strings:
	$a0 = { 68cd806868ebfc686a0b5831d252682f2f7368682f62696e89e3525389e1ebe1 }

condition:
	$a0
}

        
