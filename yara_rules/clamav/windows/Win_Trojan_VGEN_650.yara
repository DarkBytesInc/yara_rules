rule Win_Trojan_VGEN_650
{
strings:
	$a0 = { 9b009a000032005589e5b01c509a59023200bf66011e57bf00000e5731c0509a64069b009ae7059b00bf66011e }

condition:
	$a0
}

        
