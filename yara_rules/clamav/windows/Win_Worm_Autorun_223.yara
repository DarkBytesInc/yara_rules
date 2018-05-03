rule Win_Worm_Autorun_223
{
strings:
	$a0 = { 7368656c6c5c315c636f6d6d616e643d6175746f72756e2e706966 }

condition:
	$a0
}

        
