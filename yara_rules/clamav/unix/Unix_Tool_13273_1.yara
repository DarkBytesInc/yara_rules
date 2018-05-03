rule Unix_Tool_13273_1
{
strings:
	$a0 = { 9952686e2f7368682f2f626989e3515253536a3b58cd80 }

condition:
	$a0
}

        
