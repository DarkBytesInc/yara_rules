rule Win_Trojan_Small_3578
{
strings:
	$a0 = { 8bc4ff308368fc4f681e114000ff50fc83c408ff70f8b8002040003d00264000740680308c40ebf3e800000000c3 }

condition:
	$a0
}

        
