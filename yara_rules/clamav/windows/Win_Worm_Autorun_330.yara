rule Win_Worm_Autorun_330
{
strings:
	$a0 = { 5b6175746f72756e5d }
	$a1 = { 7368656c6c5c6f70656e5c636f6d6d616e643d }
	$a2 = { 2e626174 }

condition:
	$a0 and $a1 and $a2
}

        
