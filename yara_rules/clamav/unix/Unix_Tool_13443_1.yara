rule Unix_Tool_13443_1
{
strings:
	$a0 = { 31db538d4317cd8099686e2f7368682f2f626989e3505389e1b00bcd80 }

condition:
	$a0
}

        
