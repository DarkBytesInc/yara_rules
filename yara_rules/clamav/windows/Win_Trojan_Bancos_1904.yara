rule Win_Trojan_Bancos_1904
{
strings:
	$a0 = { 925945c9fb94c72b21496b710058809f0538e8cc05bb3542cfd3f664663f4172a4c3a22a6f9d16b75f91ed44288c378dae38d8bda4eba065e2bdb3503f3e3fa05af572a77100 }

condition:
	$a0
}

        
