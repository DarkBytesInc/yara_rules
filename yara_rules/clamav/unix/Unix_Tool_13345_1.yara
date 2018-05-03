rule Unix_Tool_13345_1
{
strings:
	$a0 = { 6a25586aff5b6a0959cd80 }

condition:
	$a0
}

        
