rule Unix_Tool_13255_1
{
strings:
	$a0 = { eb255931c050686e2f7368682f2f626989e35066682d6389e75051575389e750575350b03bcd80e8d6ffffff }

condition:
	$a0
}

        
