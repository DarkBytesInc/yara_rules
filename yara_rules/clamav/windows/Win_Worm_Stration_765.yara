rule Win_Worm_Stration_765
{
strings:
	$a0 = { 89ff64f3c4392c273f64684e0e0bd9381b4e32768f536bcef379900a00c21d6bce4e026d32ac25d32bc2aa8060d2e3dc104e7a9379dec0ae3e7ac60485bebcb2414576cc9e8d1b54bb9878bbd072e48f4459ce27e6ce6640dc }

condition:
	$a0
}

        
