rule Win_Trojan_Negett_1
{
strings:
	$a0 = { 2d2d2d2d2d2d2d2d2d2d2d2d2d25730a0000002577696e646972255c696a6e5c7265712e74787400000000496e746572 }

condition:
	$a0
}

        
