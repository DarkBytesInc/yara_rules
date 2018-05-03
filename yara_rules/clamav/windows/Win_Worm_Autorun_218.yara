rule Win_Worm_Autorun_218
{
strings:
	$a0 = { 5b6175746f72756e5d }
	$a1 = { 7368656c6c5c6f70656e5c636f6d6d616e643d6e7472756e2e657865 }

condition:
	$a0 and $a1
}

        
