rule Win_Trojan_Mybot_8420
{
strings:
	$a0 = { 059f302c7799e0e5f03414234702221ffe9fb0bfcd1a26ff71cec8d53ccc7f3ae8a2bca2e89ef4370531558df9feffccd626d318ae4c9775cbcf24232090da5ae9027ef58db773126ba394b3caddb58aa8ee9f2e2a }

condition:
	$a0
}

        
