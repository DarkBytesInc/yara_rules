rule Win_Worm_Autorun_248
{
strings:
	$a0 = { 7368656c6c5c6175746f5c636f6d6d616e643d7461736b6d6f6e2e657865 }

condition:
	$a0
}

        
