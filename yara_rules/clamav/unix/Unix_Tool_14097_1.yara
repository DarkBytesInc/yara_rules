rule Unix_Tool_14097_1
{
strings:
	$a0 = { 01308fe213ff2fe178460a30019001a9921a0b2701df2f2f62696e2f7368 }

condition:
	$a0
}

        
