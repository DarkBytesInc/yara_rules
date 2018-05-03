rule Unix_Tool_13354_1
{
strings:
	$a0 = { b00b9952682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
