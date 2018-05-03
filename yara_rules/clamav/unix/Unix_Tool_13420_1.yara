rule Unix_Tool_13420_1
{
strings:
	$a0 = { eb125e31c9b10bffc681065b2dd0cbade2f7eb05e8e9ffffff }

condition:
	$a0
}

        
