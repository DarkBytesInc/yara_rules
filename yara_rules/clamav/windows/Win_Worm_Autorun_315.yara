rule Win_Worm_Autorun_315
{
strings:
	$a0 = { 5b6175746f72756e5d203b[0-3]206f70656e3d }
	$a1 = { 7368656c6c657865637574653d }
	$a2 = { 7368656c6c5c6578706c6f72655c636f6d6d616e643d }
	$a3 = { 7368656c6c5c6f70656e5c636f6d6d616e643d }
	$a4 = { 7368656c6c3d6578706c6f7265 }

condition:
	$a0 and $a1 and $a2 and $a3 and $a4
}

        
