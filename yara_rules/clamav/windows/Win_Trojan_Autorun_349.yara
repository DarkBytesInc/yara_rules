rule Win_Trojan_Autorun_349
{
strings:
	$a0 = { 3633303133383333370d0a7368656c6c5c6f70656e5c436f6d6d616e643d4e5472756e2e6578650d0a }

condition:
	$a0
}

        
