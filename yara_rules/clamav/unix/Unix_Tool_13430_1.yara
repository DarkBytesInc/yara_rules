rule Unix_Tool_13430_1
{
strings:
	$a0 = { eb125e31c08846078d5e05538d1e53b03950cd80e8e9ffffff2f62696e2f7368 }

condition:
	$a0
}

        
