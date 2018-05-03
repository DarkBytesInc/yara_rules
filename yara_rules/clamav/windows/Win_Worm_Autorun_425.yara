rule Win_Worm_Autorun_425
{
strings:
	$a0 = { 5b6175746f72756e }
	$a1 = { 6f70656e3d2072[0-14]72656379636c6572 }
	$a2 = { 5c6a77676b7673712e766d78 }

condition:
	$a0 and $a1 and $a2
}

        
