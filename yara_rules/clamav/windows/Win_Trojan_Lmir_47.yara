rule Win_Trojan_Lmir_47
{
strings:
	$a0 = { 66206d6972325c456e7465725c00000050570000ffffffff18000000baa348babd48c8ed52bcfe4ad3d059cfde58b9ab47cbbe5300000000ffffffff030000002a2a2a00ffffffff0d000000cad4d3c3b0e6d3c3bba73a0d0a000000ff }

condition:
	$a0
}

        
