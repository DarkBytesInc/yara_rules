rule Win_Trojan_Agent_34691
{
strings:
	$a0 = { ff1579104000eb15a6a33c000007223e53004800000000b100c400000329f289dfc1fe1d89f801de00 }

condition:
	$a0
}

        
