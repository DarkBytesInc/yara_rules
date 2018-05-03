rule Unix_Tool_13316_1
{
strings:
	$a0 = { 6a315899cd8089c389c16a4658cd80b00b52686e2f7368682f2f626989e389d1cd80 }

condition:
	$a0
}

        
