rule Win_Worm_Autorun_317
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d6472697665725c }
	$a1 = { 5c737663686f73742e657865 }

condition:
	$a0 and $a1
}

        
