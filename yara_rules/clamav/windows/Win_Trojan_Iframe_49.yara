rule Win_Trojan_Iframe_49
{
strings:
	$a0 = { 696672616d6577696474683d306865696768743d307372633d22687474703a2f2f }
	$a1 = { 2f6d2e68746d223e3c2f696672 }

condition:
	$a0 and $a1
}

        
