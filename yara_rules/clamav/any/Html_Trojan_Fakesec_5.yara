rule Html_Trojan_Fakesec_5
{
strings:
	$a0 = { 2f7570646174652e6d6963726f736f66742e636f6d2e6b696c3169312e636f6d2f }

condition:
	$a0
}

        
