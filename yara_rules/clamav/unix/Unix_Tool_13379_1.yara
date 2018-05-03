rule Unix_Tool_13379_1
{
strings:
	$a0 = { 6a465831db31c9cd8031d26a0b5852682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
