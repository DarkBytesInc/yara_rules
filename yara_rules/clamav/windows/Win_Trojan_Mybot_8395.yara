rule Win_Trojan_Mybot_8395
{
strings:
	$a0 = { a670e957789bdce86f0961a8c5d333b674f57250e467cbbc2ce053a0a5f6005cc1b61003d97a252e431b01bed58d25d19ff7d1221e957e20b8289efceda03555f6b3c83fedf4d5fd5ad276ed9afb67d42c20496f9f }

condition:
	$a0
}

        
