rule Win_Trojan_Agent_34317
{
strings:
	$a0 = { ac04222cb0aa4975f7ff1524104000ff35641040005b508d85e8fdffff508d85f0feffffff75fc50ffd383c4106a2c58e8900800008965fcff35602040005eff75fc5fb92a000000 }

condition:
	$a0
}

        
