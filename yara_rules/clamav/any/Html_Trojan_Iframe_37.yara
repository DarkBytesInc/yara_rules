rule Html_Trojan_Iframe_37
{
strings:
	$a0 = { 3c696672616d65207372633d22687474703a2f2f777777[0-34]2f6578706c6f69742f73662e706c7822 }

condition:
	$a0
}

        
