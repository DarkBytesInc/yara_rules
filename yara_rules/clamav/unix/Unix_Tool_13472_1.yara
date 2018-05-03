rule Unix_Tool_13472_1
{
strings:
	$a0 = { 995252526a7e58cd80682f2f7368682f62696e89e352545352343bcd80 }

condition:
	$a0
}

        
