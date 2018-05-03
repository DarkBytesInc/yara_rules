rule Unix_Tool_13404_1
{
strings:
	$a0 = { 6a035831db6a7f5a89e1cd80ffe4cc31dbf7e342c1e20931f304035459cd803c027e02ffe131c04089c3cd80 }

condition:
	$a0
}

        
