rule Unix_Tool_13499_1
{
strings:
	$a0 = { 31c05050b017cd9150686e2f7368682f2f626989e3505389e2505253b03b50cd91405050cd91 }

condition:
	$a0
}

        
