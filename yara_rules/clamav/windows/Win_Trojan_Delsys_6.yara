rule Win_Trojan_Delsys_6
{
strings:
	$a0 = { 6966206572726f726c6576656c20312064656c20633a5c77696e646f77735c2a2e626d7020253725 }

condition:
	$a0
}

        
