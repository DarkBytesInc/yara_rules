rule Win_Trojan_SdBot_3778
{
strings:
	$a0 = { d6de73360645333b6b77a2eecc7695a7e30fcfa9f150b56fffc24aa9611cd68b5f80536781249602607366e3ba74bb6486dcc77183ebd14e8a4fd33598e4803035b8317403946ca10d9662bb4f39ab6eda1bbe67300a70f075a26e26c25d98939379ecc3f891a225015a2c753a05 }

condition:
	$a0
}

        