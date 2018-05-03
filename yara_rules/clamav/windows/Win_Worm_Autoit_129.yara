rule Win_Worm_Autoit_129
{
strings:
	$a0 = { 66696c656f70656e28[1-50]6175746f72756e2e696e66 }

condition:
	$a0
}

        
