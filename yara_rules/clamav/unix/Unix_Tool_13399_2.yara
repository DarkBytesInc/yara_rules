rule Unix_Tool_13399_2
{
strings:
	$a0 = { 6a0b589952682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
