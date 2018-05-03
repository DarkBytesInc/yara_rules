rule Win_Worm_Mita_2
{
strings:
	$a0 = { 7966696c65284d79576f726d2c2045646f6e6b6579202b2022766167 }
	$a1 = { 6f726d2c2045646f6e6b6579202b2022456d65696e }

condition:
	$a0 and $a1
}

        
