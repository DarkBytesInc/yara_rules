rule Win_Trojan_Delf_1678
{
strings:
	$a0 = { 558becb9150000006a006a004975f9535657b8d0ce4000e806003cac33c0556855d7400064ff306489 }

condition:
	$a0
}

        
