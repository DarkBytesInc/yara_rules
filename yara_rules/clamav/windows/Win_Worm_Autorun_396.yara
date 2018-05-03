rule Win_Worm_Autorun_396
{
strings:
	$a0 = { b85c0e50005064ff35000000006489250000000033c0 }
	$a1 = { 4155544f52554e20494e46 }
	$a2 = { 5542414853557e31455845 }

condition:
	$a0 and $a1 and $a2
}

        
