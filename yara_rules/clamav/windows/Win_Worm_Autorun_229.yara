rule Win_Worm_Autorun_229
{
strings:
	$a0 = { 5b6175746f72756e5d[0-95]7368656c6c5c6f70656e5c636f6d6d616e643d6b696e7a612e657865 }

condition:
	$a0
}

        
