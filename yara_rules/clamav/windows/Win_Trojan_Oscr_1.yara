rule Win_Trojan_Oscr_1
{
strings:
	$a0 = { 4755494d6f64653d223222 }
	$a1 = { 4578656375746546696c653d22686964636f6e3a6e6f776169743a52756e2e62617422 }

condition:
	$a0 and $a1
}

        
