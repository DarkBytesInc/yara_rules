rule Win_Trojan_QFat_2
{
strings:
	$a0 = { b30050e80702598d46f45033c050b8f40150b8020050e8800b83c408b8040050e8650059e83800 }

condition:
	$a0
}

        
