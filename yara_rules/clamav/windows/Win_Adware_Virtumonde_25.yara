rule Win_Adware_Virtumonde_25
{
strings:
	$a0 = { 0d7b3e7568b0a55b350bd7b7301eeefd018a4919c84e16ca736c3a8c466bdcb8055836b40bd02e9fa66e9ebf331fb776be8de1e7a495734633b83264c891a89e05ea4f5014a0a5d07d85394891223040 }

condition:
	$a0
}

        
