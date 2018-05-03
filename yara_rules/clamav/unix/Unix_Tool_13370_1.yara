rule Unix_Tool_13370_1
{
strings:
	$a0 = { 424d36916a0b589952682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
