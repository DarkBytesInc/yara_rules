rule Win_Spyware_527_2
{
strings:
	$a0 = { 35376716832df89d033a5b47bd7a08177f7b7cf2e4338b08c8232dbbfae76dec95840565bdf3f94cc46bcb21b1ee16b904a2f029dc01209b1e44ff6f18e94c3e7ccf51810285c45dfdd421 }

condition:
	$a0
}

        
