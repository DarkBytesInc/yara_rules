rule Win_Dropper_Agent_34709
{
strings:
	$a0 = { 558bec6889143e0064ff3500000000648925000000006a0058c600008000016a00ff15ac8d40005dc3 }

condition:
	$a0
}

        
