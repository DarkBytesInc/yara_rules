rule Win_Trojan_VKit_10
{
strings:
	$a0 = { 9a000008079a0d009f069a4f6909005589e5b824009acd02080783ec249acc019f068d7edc1657bf00000e579a230808 }

condition:
	$a0
}

        
