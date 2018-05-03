rule Unix_Tool_13368_1
{
strings:
	$a0 = { 7b5c72746631c06a0b589952682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
