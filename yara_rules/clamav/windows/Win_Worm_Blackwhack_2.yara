rule Win_Worm_Blackwhack_2
{
strings:
	$a0 = { 5b4175746f52756e5d0d0a4f70656e3d433a5c424c41434b2d4441592e455845 }

condition:
	$a0
}

        
