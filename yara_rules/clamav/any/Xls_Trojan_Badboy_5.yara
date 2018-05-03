rule Xls_Trojan_Badboy_5
{
strings:
	$a0 = { 43203d204d7367426f78284d73675328526e64526573756c74292c2076625965734e6f2c2022cfa3cdfbc4e3c4dcbdd3cadcced2b5c4d1fbc7eb212229 }

condition:
	$a0
}

        
