rule Unix_Tool_13336_1
{
strings:
	$a0 = { 6a055899526874793130682f2f2f74682f64657689e389d1cd8089c36a3658b9cfb4fffff7d1badc34fa03cd80 }

condition:
	$a0
}

        
