rule Win_Trojan_Iroffer_35
{
strings:
	$a0 = { e8be8affffc744240410f24100c7042400000000e8ea5e0000a198124300890424e86dc2ffffe8f85800008b0df812430085c90f851a010000 }

condition:
	$a0
}

        
