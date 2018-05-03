rule Unix_Tool_13475_1
{
strings:
	$a0 = { 9952686e2f7368682f2f626989e3525453536a3b58cd80 }

condition:
	$a0
}

        
