rule Win_Trojan_Melhack_1
{
strings:
	$a0 = { 5c72756e222c226d656c6861636b6572222c22633a5c77696e646f77735c6d656c6861636b65722e76627322 }

condition:
	$a0
}

        
