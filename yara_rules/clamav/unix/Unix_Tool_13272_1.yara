rule Unix_Tool_13272_1
{
strings:
	$a0 = { 31c050682f2f7368682f62696e89e350545350b03bcd80 }

condition:
	$a0
}

        
