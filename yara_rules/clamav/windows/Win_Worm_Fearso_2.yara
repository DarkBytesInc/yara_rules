rule Win_Worm_Fearso_2
{
strings:
	$a0 = { 558bec83c4c4b844fb4000e8a83cffff33c0556819fc400064ff30648920b86cfa4000a3 }
	$a1 = { 466561725f444c4c }

condition:
	$a0 and $a1
}

        
