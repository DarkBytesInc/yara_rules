rule Html_Trojan_Fakesec_6
{
strings:
	$a0 = { 6d6963726f736f66742e636f6d2e696c316c68682e6e65742f }

condition:
	$a0
}

        
