rule Unix_Tool_13378_1
{
strings:
	$a0 = { 6a175831dbcd806a2e5853cd8031d26a0b5852682f2f7368682f62696e89e3525389e1cd80 }

condition:
	$a0
}

        
