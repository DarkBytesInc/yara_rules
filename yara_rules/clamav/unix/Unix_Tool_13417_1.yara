rule Unix_Tool_13417_1
{
strings:
	$a0 = { 31c931db6a4658cd8051682f2f7368682f62696e89e3515389e199b00bcd80 }

condition:
	$a0
}

        
