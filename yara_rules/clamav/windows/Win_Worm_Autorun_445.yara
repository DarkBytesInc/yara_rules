rule Win_Worm_Autorun_445
{
strings:
	$a0 = { 5b4175746f72756e5d0d0a6f70656e3d[2-100]7368656c6c657865637574653d[2-20]7368656c6c5c4f70656e }

condition:
	$a0
}

        
