rule Unix_Tool_13446_1
{
strings:
	$a0 = { 31db8d4317cd8031d252686e2f7368682f2f626989e3525389e1b00bcd80 }

condition:
	$a0
}

        
