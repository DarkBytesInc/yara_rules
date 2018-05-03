rule Html_Trojan_Blackhole_74
{
strings:
	$a0 = { 7472797b6576616c282270726f222b22746f7479706522293e303b7d6361746368287a }

condition:
	$a0
}

        
