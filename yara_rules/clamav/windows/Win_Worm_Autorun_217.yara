rule Win_Worm_Autorun_217
{
strings:
	$a0 = { 5b6175746f72756e5d[0-47]7368656c6c5c6175746f5c636f6d6d616e643d7261766d6f6e652e657865 }

condition:
	$a0
}

        
