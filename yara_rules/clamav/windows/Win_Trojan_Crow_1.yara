rule Win_Trojan_Crow_1
{
strings:
	$a0 = { bf0a0057696e4ec34072ff2076302e32202d20ff62792043726f7762cf61720a00d460d44125738f0a008db60101f863 }

condition:
	$a0
}

        
