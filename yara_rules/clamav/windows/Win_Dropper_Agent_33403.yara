rule Win_Dropper_Agent_33403
{
strings:
	$a0 = { 8bca8d44241c83e10350f3a48d4c24408d9424a002000051526a006a006a006a006a008d8424a0000000506a00ffd5 }

condition:
	$a0
}

        
