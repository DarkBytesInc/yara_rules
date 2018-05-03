rule Html_Trojan_IFrame_8
{
strings:
	$a0 = { 474946 }
	$a1 = { 77696474683d30206865696768743d303e3c2f696672616d653e }

condition:
	$a0 and $a1
}

        
