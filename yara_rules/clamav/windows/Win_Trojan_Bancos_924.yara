rule Win_Trojan_Bancos_924
{
strings:
	$a0 = { a5459a9d08eb0ffa059641be4d54b2c93fa54ce27db0250e2679249fad5f7ad59820d8ca8a4174e34c87be75b77f5c12d05f77fdbcf5f40e0f8970bc85584747c208a36024327bc1b9910bdd6588 }

condition:
	$a0
}

        
