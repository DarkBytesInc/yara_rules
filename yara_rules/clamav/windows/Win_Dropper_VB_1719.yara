rule Win_Dropper_VB_1719
{
strings:
	$a0 = { 6879305873687036330000000000000000000006000000a4 }

condition:
	$a0
}

        
