rule Xls_Trojan_Cauli_1
{
strings:
	$a0 = { 616e73776572203d204d7367426f78282241726520796f7520646570726573736564222c2076625965734e6f2c20224c494c4c5920524553435545204d495353494f4e2229 }

condition:
	$a0
}

        