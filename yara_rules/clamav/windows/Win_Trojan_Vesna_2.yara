rule Win_Trojan_Vesna_2
{
strings:
	$a0 = { e926092b2f64706e01e91900800020007420c28e2a54554c412a64692b2f2b012b2fb1b1b101536674746a622b }

condition:
	$a0
}

        
