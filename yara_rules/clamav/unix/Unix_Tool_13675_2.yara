rule Unix_Tool_13675_2
{
strings:
	$a0 = { 31c0506a6189e39950b00b59cd80 }

condition:
	$a0
}

        
