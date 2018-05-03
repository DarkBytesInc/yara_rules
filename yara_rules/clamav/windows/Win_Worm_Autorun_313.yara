rule Win_Worm_Autorun_313
{
strings:
	$a0 = { 6175746f72756e[0-5]7368656c6c5c6f70656e5c636f6d6d616e6422202c20246e616d6520262024657865 }

condition:
	$a0
}

        
