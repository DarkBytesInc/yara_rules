rule Win_Dropper_Agent_34310
{
strings:
	$a0 = { 558becb9080000006a006a004975f95356b80c394000e89dfaffff33c055687e3b400064ff30648920b81c574000ba943b4000e814f5ffff }

condition:
	$a0
}

        
