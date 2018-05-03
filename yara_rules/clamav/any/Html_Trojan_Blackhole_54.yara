rule Html_Trojan_Blackhole_54
{
strings:
	$a0 = { 6665776267617a722b2b7d63617463682865626777656729 }

condition:
	$a0
}

        
