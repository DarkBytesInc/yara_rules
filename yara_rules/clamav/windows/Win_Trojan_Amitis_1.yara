rule Win_Trojan_Amitis_1
{
strings:
	$a0 = { 2e646c4900000000ffffffff07000000646c4966696c6500ffffffff1a000000646c4966696c655c7368656c6c5c6f70656e5c636f6d6d616e64 }

condition:
	$a0
}

        
