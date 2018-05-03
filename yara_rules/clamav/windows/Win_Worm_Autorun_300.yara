rule Win_Worm_Autorun_300
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d74656c2e657865 }

condition:
	$a0
}

        
