rule Html_Trojan_Iframe_53
{
strings:
	$a0 = { 726d632e636f6d2f696672616d6566696c652e6a73223e3c2f7363726970743e3c2f74723e3c74723e3c7464 }

condition:
	$a0
}

        
