rule Win_Trojan_Iframe_43
{
strings:
	$a0 = { 3c696672616d65207372633d22687474703a2f2f }
	$a1 = { 2e72753a383038302f696e6465782e70687022 }
	$a2 = { 6974793a2068696464656e }

condition:
	$a0 and $a1 and $a2
}

        
