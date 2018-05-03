rule Doc_Trojan_Marker_15
{
strings:
	$a0 = { 56616c7565203d204d7367426f782822d1e5e3eee4edff20effff2ede8f6e02c2031332e20d1ebe5e4eee2e0f2e5ebfcedee2c20ede020e2e0f8e5e920f2e0f7eae520f1f2 }

condition:
	$a0
}

        
