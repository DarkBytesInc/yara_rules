rule Win_Trojan_Vgen_84
{
strings:
	$a0 = { 9a0000e1009a00007f005589e531c09a7c02e1009ac0017f00bf58021e57bf00000e5731c0509ab406e1009ae505e100 }

condition:
	$a0
}

        
