rule Win_Trojan_Lineage_281
{
strings:
	$a0 = { f5f556f5f58bf6f5f52bf7f5f585f6f5f55ef5f50f8409000000f5f5e93c000000f5f581c6facf75db81c606308a2481c6a074153d81eef0a7c5df81ee10583a2081eee61fee0053bb4460820881c3fe4a56bb03f35be9a5fffffff5 }

condition:
	$a0
}

        
