rule Unix_Tool_14113_1
{
strings:
	$a0 = { 01308fe213ff2fe1241b201c172701df78460a30019001a9921a0b2701df2f2f62696e2f7368 }

condition:
	$a0
}

        
