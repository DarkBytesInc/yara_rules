rule Win_Trojan_VGEN_526
{
strings:
	$a0 = { 89261e01e8fe02e80a03e85003eb098b261e01e89203b001b44ccd210000000d0a426f6f7454687275202d20546865 }

condition:
	$a0
}

        
