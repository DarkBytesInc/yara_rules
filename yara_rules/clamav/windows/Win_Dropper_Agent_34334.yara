rule Win_Dropper_Agent_34334
{
strings:
	$a0 = { 558becb9080000006a006a004975f9515356b80c394000e89cfaffff33c05568ba3b400064ff30648920b81c574000bad03b4000e813f5ffff }

condition:
	$a0
}

        
