rule Win_Trojan__0371_0006_000_1
{
strings:
	$a0 = { 28a38400b80057cc5152b97201b44099cc7210b8004233c999ccb90400ba8200b440ccb801 }

condition:
	$a0
}

        
