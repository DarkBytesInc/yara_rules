rule Win_Trojan_Sdbot_7
{
strings:
	$a0 = { c2b2c1359bd4a8bd2b4117eada28f913fa49e1dd78ce95f0327a82ee60db08aed83df0d5f2a95e7bd215fb22be4aa67dcfc36ffa40b9940c9bb395b0d2d0db9224f4c05fe9e27dd2fa04d447d7a3a4ac03a62c5d0fdae47d3dd86bedb0c3218dc3c7af603bd9c5778ae69781f5fb5075fd33da027a71c0dca9e622 }

condition:
	$a0
}

        
