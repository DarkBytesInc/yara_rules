rule Win_Trojan_VGEN_195
{
strings:
	$a0 = { 04008db6bc02ffd62bfca615b254150791502d3291500d339122640464046855057b9160b7fd5ef91f021d1a2cd892 }

condition:
	$a0
}

        
