rule Win_Trojan_Vgen_155
{
strings:
	$a0 = { 9a0000e0009a00007e005589e531c09a7c02e0009ac0017e00bf58021e57bf00000e5731c0509ab406e0009ae505e000 }

condition:
	$a0
}

        
