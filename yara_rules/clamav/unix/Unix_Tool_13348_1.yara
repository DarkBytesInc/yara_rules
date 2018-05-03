rule Unix_Tool_13348_1
{
strings:
	$a0 = { 6a1958995289e3cd8040cd80 }

condition:
	$a0
}

        
