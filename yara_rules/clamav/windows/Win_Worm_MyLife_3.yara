rule Win_Worm_MyLife_3
{
strings:
	$a0 = { eb7274735f4675636b696e675f746e5bfb866f25742e4d70650bea611a2d31acdd64d02a2ef4683c1d796eafddf680340790 }

condition:
	$a0
}

        
