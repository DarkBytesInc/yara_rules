rule Win_Trojan_Delf_1516
{
strings:
	$a0 = { 6a006a004975f9535657b818461413e8bcf0ffff33c055684149141364ff30648920909090b86d000000 }

condition:
	$a0
}

        
