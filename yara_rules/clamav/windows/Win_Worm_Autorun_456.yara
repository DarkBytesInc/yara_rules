rule Win_Worm_Autorun_456
{
strings:
	$a0 = { 6f70656e3d[0-6]2e657865 }
	$a1 = { 7368656c6c5c6f70656e5c636f6d6d616e643d[0-6]2e657865 }
	$a2 = { 7368656c6c5c[0-22]2e657865 }

condition:
	$a0 and $a1 and $a2
}

        
