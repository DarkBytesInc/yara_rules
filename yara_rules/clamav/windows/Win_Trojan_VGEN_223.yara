rule Win_Trojan_VGEN_223
{
strings:
	$a0 = { 3cf07210e86a06e86706528d168802b409cd215ac306535733c0bf11021e8ed8833d007510b82135cd214f8cc089 }

condition:
	$a0
}

        
