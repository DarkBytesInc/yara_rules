rule Unix_Tool_13358_1
{
strings:
	$a0 = { 31c0bb088404085389e131d2b00bcd80 }

condition:
	$a0
}

        
