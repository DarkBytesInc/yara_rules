rule Win_Trojan_Agent_35562
{
strings:
	$a0 = { e806960000e991190100558bec83ec18c745e8e0030000c7 }
	$a1 = { 667364667366612e626174[0-14]2d72202d742030202d66 }

condition:
	$a0 and $a1
}

        
