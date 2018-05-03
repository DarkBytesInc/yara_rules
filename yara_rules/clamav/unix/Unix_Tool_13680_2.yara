rule Unix_Tool_13680_2
{
strings:
	$a0 = { eb115e31c9b106806c0eff0180e90175f6eb05e8eaffffffb103ce81ecfb }

condition:
	$a0
}

        
