rule Win_Trojan_Killav_149
{
strings:
	$a0 = { 25207370792a[0-1]25636f6c64252062756c6c6775617264 }
	$a1 = { 6578706c6f7265722e657865202561252e626174 }

condition:
	$a0 and $a1
}

        
