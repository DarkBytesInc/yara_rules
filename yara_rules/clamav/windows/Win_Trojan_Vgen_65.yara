rule Win_Trojan_Vgen_65
{
strings:
	$a0 = { 662027255f70617373696f6e253d3d2720676f746f205f70617373696f6e0d0a3a3a2a2a2a2a20484f5354202a2a }

condition:
	$a0
}

        
