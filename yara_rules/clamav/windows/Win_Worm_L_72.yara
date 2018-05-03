rule Win_Worm_L_72
{
strings:
	$a0 = { 613a0d0a666f726d617420633a0d0a476f746f2061 }

condition:
	$a0
}

        
