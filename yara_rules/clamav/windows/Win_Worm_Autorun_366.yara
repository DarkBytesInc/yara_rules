rule Win_Worm_Autorun_366
{
strings:
	$a0 = { 6f70656e3d73797374656d5c }
	$a1 = { 5c73797374656d33322e657865 }

condition:
	$a0 and $a1
}

        
