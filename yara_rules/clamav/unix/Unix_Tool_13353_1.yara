rule Unix_Tool_13353_1
{
strings:
	$a0 = { b01731dbcd80b00b9952682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
