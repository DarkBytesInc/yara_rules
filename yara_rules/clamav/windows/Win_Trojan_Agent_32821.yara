rule Win_Trojan_Agent_32821
{
strings:
	$a0 = { b56303512967d84cedaee44bc6366b9d833d9ba08209a47b7d222d6e00d0b2c841e687362812fb1ee036c687876e386f7ce31db7b2c670b9d3b2c13ba7c4e047a3 }

condition:
	$a0
}

        
