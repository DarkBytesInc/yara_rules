rule Win_Trojan_Deltree_1
{
strings:
	$a0 = { 6563686f206175746f657865632e332064656c74726565202f79205c77696e646f77735c }

condition:
	$a0
}

        
