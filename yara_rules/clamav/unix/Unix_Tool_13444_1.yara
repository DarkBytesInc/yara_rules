rule Unix_Tool_13444_1
{
strings:
	$a0 = { 31c050686e2f7368682f2f626989e399525389e1b00bcd80 }

condition:
	$a0
}

        
