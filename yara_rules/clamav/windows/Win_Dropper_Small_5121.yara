rule Win_Dropper_Small_5121
{
strings:
	$a0 = { d777cbff433a5c5365727665722e65958125145c912327ed0333620334480343deff9f0f68307420707230 }

condition:
	$a0
}

        
