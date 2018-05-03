rule Win_Worm_Autorun_382
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d636f6e6669675c }
	$a1 = { 2e657865 }

condition:
	$a0 and $a1
}

        
