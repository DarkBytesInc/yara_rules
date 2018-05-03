rule Win_Worm_Autorun_230
{
strings:
	$a0 = { 5c72656379636c652e76627322 }
	$a1 = { 70617468202620225c736176656d6f64652e7379732e76627322 }

condition:
	$a0 and $a1
}

        
