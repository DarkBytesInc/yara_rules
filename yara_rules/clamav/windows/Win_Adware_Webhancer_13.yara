rule Win_Adware_Webhancer_13
{
strings:
	$a0 = { 52455c77656248616e6365720000547970654c69625c7b43384342333837302d4344 }

condition:
	$a0
}

        
