rule Win_Trojan_Bancos_810
{
strings:
	$a0 = { 9a9d9d16aa1164a9922235bf17f100da671193ffc57fc92afca020d69c211282d852336a82e4425e5d5beaecebd19e34c913a6d832454cd8be596b246b2309085bfb22f73739 }

condition:
	$a0
}

        
