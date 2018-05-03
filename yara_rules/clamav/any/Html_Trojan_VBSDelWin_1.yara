rule Html_Trojan_VBSDelWin_1
{
strings:
	$a0 = { 57726974654c696e65282264656c20633a5c77696e646f77735c73797374656d5c2a2e2a2229 }

condition:
	$a0
}

        
