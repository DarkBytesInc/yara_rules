rule Win_Trojan_YB_6
{
strings:
	$a0 = { 9201b440cd21b8004233c999cd218b8481012d030089846401b904008d946301b440cd21b80157 }

condition:
	$a0
}

        
