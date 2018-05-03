rule Html_Trojan_Blackhole_62
{
strings:
	$a0 = { 6361746368286136626133347929 }

condition:
	$a0
}

        
