rule Unix_Tool_13365_1
{
strings:
	$a0 = { 9931c052686e2f7368682f2f626989e3525389e1b00bcd80 }

condition:
	$a0
}

        
