rule Win_Worm_Req_1
{
strings:
	$a0 = { 0a643d6420262063687228417363284d696428692c6a2c3129292d3329 }

condition:
	$a0
}

        
