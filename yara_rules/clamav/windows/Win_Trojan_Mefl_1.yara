rule Win_Trojan_Mefl_1
{
strings:
	$a0 = { e800005e83ee0356b85aa5cd213da55a74531e06560e1f8cc0488ec026832e0300412603060300408ec0b91000bf0000 }

condition:
	$a0
}

        
