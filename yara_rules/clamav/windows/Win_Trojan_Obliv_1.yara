rule Win_Trojan_Obliv_1
{
strings:
	$a0 = { 803d44414000007531c785ccfbffff00000000683c404000e8500b000083c40489c783c70157683c4040006a01 }

condition:
	$a0
}

        
