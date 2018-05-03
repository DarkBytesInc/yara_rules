rule Win_Worm_Agent_34547
{
strings:
	$a0 = { 68c414141356ffd385c07509c645fb01e95afaffff68b814141356ffd385c00f854afaffff8a65b48a45c88945d4e93cfaffff }

condition:
	$a0
}

        
