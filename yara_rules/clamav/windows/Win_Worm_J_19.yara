rule Win_Worm_J_19
{
strings:
	$a0 = { 5b6175746f72756e5d[0-105]7368656c6c5c6f70656e5c636f6d6d616e64203d20777363726970742e65786520 }
	$a1 = { 2e6a73 }

condition:
	$a0 and $a1
}

        
