rule Unix_Tool_13390_1
{
strings:
	$a0 = { 6a055831c951b5086864726f6d6865762f63682f2f2f6489e3cd8089c3b03666b90953cd8040cd80 }

condition:
	$a0
}

        
