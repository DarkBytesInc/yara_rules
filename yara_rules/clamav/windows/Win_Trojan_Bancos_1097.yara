rule Win_Trojan_Bancos_1097
{
strings:
	$a0 = { c803851e615fee5274377b88e519700ef91fd6d7ce156b39c2a01c51a6d2ebdcef130f1500bc7622f449d8d9f37aa1ff6b4d8f32ed43eebcaa52116a09840703229190463a3fb0cc387f3120a63d }

condition:
	$a0
}

        
