rule Doc_Trojan_Mercado_1
{
strings:
	$a0 = { 633a5c2a2e647276 }
	$a1 = { 633a5c77696e646f77735c73797374656d5c2a2e647276 }
	$a2 = { 492068617665 }

condition:
	$a0 and $a1 and $a2
}

        
