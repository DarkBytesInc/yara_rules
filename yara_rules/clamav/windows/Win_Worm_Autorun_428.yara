rule Win_Worm_Autorun_428
{
strings:
	$a0 = { 5b6175746f72756e5d0d0a6f70656e3d6175746f70726f6d70742e657865 }

condition:
	$a0
}

        
