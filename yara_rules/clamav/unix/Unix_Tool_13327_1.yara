rule Unix_Tool_13327_1
{
strings:
	$a0 = { 31c05068626f6f74686e2f7265682f73626989e35089e25389e1b00bcd80 }

condition:
	$a0
}

        
