rule Win_Worm_Autorun_276
{
strings:
	$a0 = { 5b6175746f72756e5d[0-105]7368656c6c5c6f70656e5c636f6d6d616e643d77696e642e657865 }

condition:
	$a0
}

        
