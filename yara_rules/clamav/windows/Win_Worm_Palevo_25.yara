rule Win_Worm_Palevo_25
{
strings:
	$a0 = { 558becb9600000006a006a004975f9b8a8984000e8dfb7ffff33c055686aa940 }

condition:
	$a0
}

        
