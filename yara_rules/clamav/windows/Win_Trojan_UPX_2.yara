rule Win_Trojan_UPX_2
{
strings:
	$a0 = { 4d494d452dd09ba3d1de19312e3012825b022d8858d5115c3a052cdcb8d00b7f6d69b3643b916f5a77c3043b9a3d2247222e834676a95d2d00 }

condition:
	$a0
}

        
