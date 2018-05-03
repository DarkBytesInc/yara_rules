rule Win_Worm_Mytob_475
{
strings:
	$a0 = { 558bec81ec08010000e85b040000e82a000000680801 }
	$a1 = { 7733322e7061696e6b696c6c6572 }

condition:
	$a0 and $a1
}

        
