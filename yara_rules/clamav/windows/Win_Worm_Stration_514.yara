rule Win_Worm_Stration_514
{
strings:
	$a0 = { 5c0000002e657865000000 }
	$a1 = { cccccc83ec10578b7c241885ff750883c8ff5f83c410c3566a066a016a02e801002fec8bf0 }

condition:
	$a0 and $a1
}

        
