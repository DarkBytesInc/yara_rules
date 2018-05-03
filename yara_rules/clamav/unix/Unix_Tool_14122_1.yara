rule Unix_Tool_14122_1
{
strings:
	$a0 = { 01608fe216ff2fe178460c30ff21ff310f2701df012701df }

condition:
	$a0
}

        
