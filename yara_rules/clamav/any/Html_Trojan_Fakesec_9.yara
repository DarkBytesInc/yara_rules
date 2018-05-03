rule Html_Trojan_Fakesec_9
{
strings:
	$a0 = { 687474703a2f2f[0-10]616e7469766972[0-10]2e6f7572746f6f6c6261722e636f6d2f }

condition:
	$a0
}

        
