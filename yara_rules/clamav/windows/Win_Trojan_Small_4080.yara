rule Win_Trojan_Small_4080
{
strings:
	$a0 = { e84f000000c3eb6181c5ff8bffff83f5ff01ddeb4a81efdc07000089f8eb5d }

condition:
	$a0
}

        
