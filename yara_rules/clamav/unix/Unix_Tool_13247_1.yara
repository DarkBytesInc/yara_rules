rule Unix_Tool_13247_1
{
strings:
	$a0 = { 31c050b01750cd8050686e2f7368682f2f626989e350545350b03bcd80 }

condition:
	$a0
}

        
