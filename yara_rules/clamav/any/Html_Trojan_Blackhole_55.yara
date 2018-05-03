rule Html_Trojan_Blackhole_55
{
strings:
	$a0 = { 796233347962347a72652b2b7d6361746368287265627277657929 }

condition:
	$a0
}

        
