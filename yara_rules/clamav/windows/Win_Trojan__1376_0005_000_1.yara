rule Win_Trojan__1376_0005_000_1
{
strings:
	$a0 = { 2d03008986b501b440b90c018d960501cd21b800422bc999cd21b440b904008d96b401cd21fe }

condition:
	$a0
}

        
