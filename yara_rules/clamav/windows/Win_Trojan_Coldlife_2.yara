rule Win_Trojan_Coldlife_2
{
strings:
	$a0 = { 6d636f707920706f726e207465747269732e657865[0-9]706f726e20637261636b65722e657865 }

condition:
	$a0
}

        
