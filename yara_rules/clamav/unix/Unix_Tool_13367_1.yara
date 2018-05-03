rule Unix_Tool_13367_1
{
strings:
	$a0 = { 504b0304246a0b589952682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
