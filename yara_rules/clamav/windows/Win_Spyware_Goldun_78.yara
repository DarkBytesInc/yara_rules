rule Win_Spyware_Goldun_78
{
strings:
	$a0 = { 68ad140010688c7d0010e85302000057688c7d0010e848020000b9d613001083e90568f7530010 }

condition:
	$a0
}

        
