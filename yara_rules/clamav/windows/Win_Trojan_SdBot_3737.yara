rule Win_Trojan_SdBot_3737
{
strings:
	$a0 = { f62a2a0ffa3c9dfafafafa1cf061622bfafaa3633616f6e0838c30341bfbfafafa1c7bfa1cf0fa1c050f61857ef6f635d7f00ffa3c9dfafafafa1cf0615b2bfafaa3d33616f661d6ecfafae143e0fafafa1c79fa1c7bfa3c9dfafafafa1cf0610c6ffafae103c2fafa99285fb348 }

condition:
	$a0
}

        
