rule Unix_Tool_13377_1
{
strings:
	$a0 = { 6a175831dbcd8031d26a0b5852682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
