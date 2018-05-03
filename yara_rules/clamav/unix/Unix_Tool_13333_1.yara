rule Unix_Tool_13333_1
{
strings:
	$a0 = { 31db8d431799cd8031c951686e2f7368682f2f62698d410b89e3cd80 }

condition:
	$a0
}

        
