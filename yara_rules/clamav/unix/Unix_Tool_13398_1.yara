rule Unix_Tool_13398_1
{
strings:
	$a0 = { 6a465831db31c9cd8099b00b52682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
