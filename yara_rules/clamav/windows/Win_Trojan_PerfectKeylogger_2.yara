rule Win_Trojan_PerfectKeylogger_2
{
strings:
	$a0 = { 317a1e25f2ded52693af08d0d6dedb118def4610befe96b921f8b323ac69755a66226d9d3ee5da70519257f46a4d41c1d9f3fb75e770e11d19eabfd295b0fdf8b839c1adc4460c64b8302d9857de1a3d1ee26459e66670a824d0a9f6fc6438b3 }

condition:
	$a0
}

        
