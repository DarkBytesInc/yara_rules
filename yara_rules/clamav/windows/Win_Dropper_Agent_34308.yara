rule Win_Dropper_Agent_34308
{
strings:
	$a0 = { eb205657e89d000000e84a0000006a00e8730000006a006a006a006a00e812000000e802ffffff6a00e81e000000 }

condition:
	$a0
}

        
