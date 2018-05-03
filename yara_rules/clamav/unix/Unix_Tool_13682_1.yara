rule Unix_Tool_13682_1
{
strings:
	$a0 = { 6a1858cd8050505b596a4658cd8050682f2f7368682f62696e89e39931c9b00bcd80 }

condition:
	$a0
}

        
