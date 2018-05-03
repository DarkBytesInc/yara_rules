rule Unix_Tool_13704_1
{
strings:
	$a0 = { 31c050686e2f7368682f2f626989e3505389e2505253b03b50cd91 }

condition:
	$a0
}

        
