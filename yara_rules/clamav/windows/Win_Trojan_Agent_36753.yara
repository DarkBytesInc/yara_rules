rule Win_Trojan_Agent_36753
{
strings:
	$a0 = { 6d616c776172657265736561726368[0-250]73696d756c6174696f6e2e657865 }

condition:
	$a0
}

        
