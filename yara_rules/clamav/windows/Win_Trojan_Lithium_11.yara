rule Win_Trojan_Lithium_11
{
strings:
	$a0 = { 48655d05fced696768183101074361700106bf3dacaa246f74611063204950207f5601db4e6f0866212076312e30feff00c1 }

condition:
	$a0
}

        
