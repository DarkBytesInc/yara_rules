rule Win_Trojan_Bancos_1444
{
strings:
	$a0 = { 66dd91026da72c024fa5dce4230138f1241a71fcd434530c0e7c29f951df82c9feed5ed49fda9014ea19dc5b9283f575ecfdbd6a4287805c55d52268262e667bbdb63f167fc72bc035b6d985a83ace1c4ef37c7aaef1222e49fe8f6b0ae671c3 }

condition:
	$a0
}

        
