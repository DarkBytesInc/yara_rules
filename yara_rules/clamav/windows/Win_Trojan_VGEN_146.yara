rule Win_Trojan_VGEN_146
{
strings:
	$a0 = { 82005589e5b802029a3005820081ec02029a0a09820009c07e5e9a0a0982008846ffb0013a46ff774fa2f701eb }

condition:
	$a0
}

        
