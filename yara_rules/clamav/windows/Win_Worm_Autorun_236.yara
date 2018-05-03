rule Win_Worm_Autorun_236
{
strings:
	$a0 = { 5b6175746f72756e5d[0-38]7368656c6c5c6f70656e5c636f6d6d616e643d7365637265742e657865 }

condition:
	$a0
}

        
