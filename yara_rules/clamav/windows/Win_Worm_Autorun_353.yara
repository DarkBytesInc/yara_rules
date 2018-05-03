rule Win_Worm_Autorun_353
{
strings:
	$a0 = { 7368656c6c5c6175746f5c636f6d6d616e643d696e662e657865 }

condition:
	$a0
}

        
