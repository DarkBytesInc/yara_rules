rule Unix_Tool_13389_1
{
strings:
	$a0 = { 6a055831c951b5086864726f6d6865762f63682f2f2f6489e3cd8089c366b90953b036cd80ebfa }

condition:
	$a0
}

        
