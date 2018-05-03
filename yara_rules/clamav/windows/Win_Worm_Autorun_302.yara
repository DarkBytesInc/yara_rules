rule Win_Worm_Autorun_302
{
strings:
	$a0 = { 7368656c6c5c28266f295c636f6d6d616e643d72656379636c65725c756368656c702e657865 }

condition:
	$a0
}

        
