rule Win_Worm_Autorun_332
{
strings:
	$a0 = { 757362636173682e657865[0-35]7368656c6c5c6f70656e5c436f6d6d616e643d }
	$a1 = { 5c647269766572735c736d73732e657865 }

condition:
	$a0 and $a1
}

        
