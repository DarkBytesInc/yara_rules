rule Unix_Tool_13397_1
{
strings:
	$a0 = { 6a5858bbaddee1feb969191228ba67452301cd80 }

condition:
	$a0
}

        
