rule Html_Trojan_VBSShutdown_2
{
strings:
	$a0 = { 5368656c6c2e52756e2252756e646c6c33322e657865557365722e6578652c4578697457696e646f7773 }

condition:
	$a0
}

        
