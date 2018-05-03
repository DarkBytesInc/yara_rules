rule Unix_Tool_13326_1
{
strings:
	$a0 = { 31c05066686c35686c6c616c686e2f6b69682f73626989e35089e25389e1b00bcd80 }

condition:
	$a0
}

        
