rule Win_Trojan_Small_4078
{
strings:
	$a0 = { e84f000000c3eb6181c5ffbdffff83f5ff01ddeb4a81efdc07000089f8eb5d5589e583ec08c745f800000000c745fc01000000e8000000005b81e30000ffff8b1380fa4d7404eb04ebf5c9c3 }

condition:
	$a0
}

        
