rule Html_Trojan_Fakesec_10
{
strings:
	$a0 = { 687474703a2f2f7777772e706f6f676f2e726f2f }

condition:
	$a0
}

        
