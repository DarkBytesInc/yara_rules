rule Win_Worm_Autorun_235
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d777363726970742e65786520257e6e302e766265 }

condition:
	$a0
}

        
