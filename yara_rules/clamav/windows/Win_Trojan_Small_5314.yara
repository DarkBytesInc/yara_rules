rule Win_Trojan_Small_5314
{
strings:
	$a0 = { c9e10fb860b6e3f8f822b840fccdcf3bbde625b7d00e200e63cf2220e1e10fb84db641bbf8cd527c11cd44dc10cde5c0080ed017572b2b11bc242720f9ddcfb862d6cecd30de0fb848cde5f4080ed043e938d0221c243ab8f7e323c838ce54786d005bf528de0fb84ecda73db942f50ef8a550 }

condition:
	$a0
}

        
