rule Win_Spyware_3306_1
{
strings:
	$a0 = { 6578650000547769737465722e6578 }
	$a1 = { 373000005261764d6f6e2e6578650000536f66 }

condition:
	$a0 and $a1
}

        
