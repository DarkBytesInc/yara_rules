rule Win_Trojan_VBS_46
{
strings:
	$a0 = { 70726f67203d2070726f672026202237362c36392c37322c36662c36652c36642c36352c3665 }
	$a1 = { 3d2053706c69742870726f672c20222c22290d0a2070617468203d2022646f6d6d6167652e65 }

condition:
	$a0 and $a1
}

        