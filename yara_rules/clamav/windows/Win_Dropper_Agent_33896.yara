rule Win_Dropper_Agent_33896
{
strings:
	$a0 = { e800003324e80000202433c05a595964891068a84d40008d45e8ba02000000e800002138 }

condition:
	$a0
}

        
