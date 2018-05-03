rule Html_Trojan_IRCCloner_8
{
strings:
	$a0 = { 6e69636b[10-100]736572766572 }
	$a1 = { 616263322e646c6c[0-10]72656d6f74652e696e69[0-10]616263642e6a7067 }

condition:
	$a0 and $a1
}

        
