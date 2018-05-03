rule Win_Worm_Autorun_383
{
strings:
	$a0 = { 416374696f6e3d4175746f72756e }
	$a1 = { 6175746f72756e2e696e66006d2e657865 }
	$a2 = { 61003a005c0000006c006100730074005f0063006f }

condition:
	$a0 and $a1 and $a2
}

        
