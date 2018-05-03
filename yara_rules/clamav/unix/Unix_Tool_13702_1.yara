rule Unix_Tool_13702_1
{
strings:
	$a0 = { 6a0b589952 }
	$a1 = { 89e1526a74682f776765682f62696e682f75737289e352515389e1cd8040cd80 }

condition:
	$a0 and $a1
}

        
