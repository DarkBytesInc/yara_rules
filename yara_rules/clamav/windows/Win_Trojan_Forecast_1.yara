rule Win_Trojan_Forecast_1
{
strings:
	$a0 = { 940020206a0220007402a30001000c0024208a0202002700f4006000ffffad0000002700f4006700ffff65 }

condition:
	$a0
}

        
