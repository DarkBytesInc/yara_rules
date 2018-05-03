rule Unix_Tool_13698_1
{
strings:
	$a0 = { eb115e31c9b121806c0eff0180e90175f6eb05e8eaffffff6b0c599a5367692e718ae2536b6969306362746930636a6f8ae45352548ae2ce81 }

condition:
	$a0
}

        
