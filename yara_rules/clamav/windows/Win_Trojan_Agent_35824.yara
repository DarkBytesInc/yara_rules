rule Win_Trojan_Agent_35824
{
strings:
	$a0 = { 558bec565733ff8b34252c504000578bc6ffd0578bc6ffd0508b0554504000ffd05985c00f85700000006a616a668b05 }

condition:
	$a0
}

        
