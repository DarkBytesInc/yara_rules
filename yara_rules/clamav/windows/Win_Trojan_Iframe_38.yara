rule Win_Trojan_Iframe_38
{
strings:
	$a0 = { 3c696672616d65207372633d22687474703a2f2f6a6c2e63687572612e706c2f72632f22[0-16]6e6f6e65223e3c2f69 }

condition:
	$a0
}

        
