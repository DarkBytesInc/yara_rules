rule Unix_Tool_13356_1
{
strings:
	$a0 = { 6a465831db31c9cd80eb215f6a0b58995266682d6389e652682f2f7368682f62696e89e35257565389e1cd80e8daffffff }

condition:
	$a0
}

        
