rule Win_Ircbot_Breaker_2
{
strings:
	$a0 = { 425245414b455228290d0a0d0a272a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0d0a27546865205642532f427265616b }

condition:
	$a0
}

        
