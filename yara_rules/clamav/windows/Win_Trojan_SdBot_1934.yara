rule Win_Trojan_SdBot_1934
{
strings:
	$a0 = { b761d8b6fd99806426fa0058a4dbb141eccd6d21a0e961e035f1cb5b642a1416d96cbce9d32484337d1e51819f2e08cf6faabfd867d32b70e1cd948cbf67888769a4e9f49ce8b862f86812c59db9f5d0b0eabee6f7292ae92e6cfd67deed03 }

condition:
	$a0
}

        
