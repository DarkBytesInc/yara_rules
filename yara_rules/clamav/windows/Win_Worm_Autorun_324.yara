rule Win_Worm_Autorun_324
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d726573746f72655c }
	$a1 = { 5c73776565742e657865 }

condition:
	$a0 and $a1
}

        
