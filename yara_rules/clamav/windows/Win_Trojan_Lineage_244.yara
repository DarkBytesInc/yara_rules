rule Win_Trojan_Lineage_244
{
strings:
	$a0 = { 8179ec16b523165c653598557ad48c551aa4f9121a056fffacab55d0f230e30b0c440bbdedbc1d23515571e6063838b2e711b67369b483ec28bf2cb68af08f1dd3308997ee2a9cf0a4f67efeaca562b91aa8a2e3f7c494dbd908f685 }

condition:
	$a0
}

        
