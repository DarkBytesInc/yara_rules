rule Win_Trojan_C_288
{
strings:
	$a0 = { 64656c20633a5c6175746f657865632e626174[0-18]64656c20633a5c636f6d6d616e642e636f6d }

condition:
	$a0
}

        
