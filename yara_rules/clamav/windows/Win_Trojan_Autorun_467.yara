rule Win_Trojan_Autorun_467
{
strings:
	$a0 = { 7368656c6c5c6f70656e5c636f6d6d616e643d6369616f5c5c5c616d6f72652e657865 }

condition:
	$a0
}

        
