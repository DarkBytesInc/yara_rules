rule Win_Trojan_Agent_33721
{
strings:
	$a0 = { f0d7e2b5e0f282dac41f0dbc01bf67410563edcf050c0a1df628747f9232ab4e6cd77a8d91bc5ec6fce71965c7795b89b9d02a5f20ae374fcd23a6696bf086c45468431be62a3dcbae9106cbae31ffc01fc98370ab7a91816b89d7969e1ef3 }

condition:
	$a0
}

        
