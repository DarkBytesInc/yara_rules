rule Win_Trojan_VCC_10
{
strings:
	$a0 = { b904008d96f400cd21fe86f800b802422bc999cd21b440b957018d960600cd21b43ecd21c3 }

condition:
	$a0
}

        
