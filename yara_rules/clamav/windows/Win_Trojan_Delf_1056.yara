rule Win_Trojan_Delf_1056
{
strings:
	$a0 = { d2930b4a6d77e2fd103e0b5c683d0a4a72e8f2bdb449e2d9c13d0bbe21b8d7c7edb2c0bda44de285123e0b5e7f3e30bfb4515abd32f4b44bf93d0abdb44de2450f3e0b4a47510bc0fdb1c08cfa3d0a4ad1fba649f9af415aa8b2c35246920b4a6d6d0f65 }

condition:
	$a0
}

        
