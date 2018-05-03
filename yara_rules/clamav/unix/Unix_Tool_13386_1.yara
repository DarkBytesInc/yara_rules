rule Unix_Tool_13386_1
{
strings:
	$a0 = { 6a30586a055beb0559cd80cc40e8f6ffffff99b00b52682f2f7368682f62696e89e3525354ebe1 }

condition:
	$a0
}

        
