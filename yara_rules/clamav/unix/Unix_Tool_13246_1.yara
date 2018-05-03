rule Unix_Tool_13246_1
{
strings:
	$a0 = { eb0d5f31c05089e2525754b03bcd80e8eeffffff }

condition:
	$a0
}

        
