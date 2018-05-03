rule Win_Worm_Autorun_331
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d }
	$a1 = { 5c73797374656d2e657865 }

condition:
	$a0 and $a1
}

        
