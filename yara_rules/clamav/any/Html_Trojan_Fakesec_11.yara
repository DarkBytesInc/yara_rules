rule Html_Trojan_Fakesec_11
{
strings:
	$a0 = { 687474703a2f2f66662e636f6e647569742d646f776e6c6f61642e636f6d }

condition:
	$a0
}

        
