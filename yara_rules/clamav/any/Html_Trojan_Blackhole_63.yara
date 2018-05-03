rule Html_Trojan_Blackhole_63
{
strings:
	$a0 = { 7472797b66617765622b2b7d63617463682862746177657462 }

condition:
	$a0
}

        
