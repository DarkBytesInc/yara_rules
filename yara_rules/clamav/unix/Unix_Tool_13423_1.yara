rule Unix_Tool_13423_1
{
strings:
	$a0 = { 31c9f7e1040b52682f617368682f62696e89e3cd80 }

condition:
	$a0
}

        
