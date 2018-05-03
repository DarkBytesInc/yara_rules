rule Unix_Tool_13264_1
{
strings:
	$a0 = { 31c06a09485040b02550cd80 }

condition:
	$a0
}

        
