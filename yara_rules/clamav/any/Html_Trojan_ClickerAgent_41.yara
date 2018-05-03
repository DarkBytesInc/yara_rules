rule Html_Trojan_ClickerAgent_41
{
strings:
	$a0 = { 75636b00000000ffffffff0e0000007364646d2c736e6d68622d626e6c0000ffffffff0f00000063687173782c75646d74722d626e6c00ffffffff0c0000006f686272 }

condition:
	$a0
}

        
