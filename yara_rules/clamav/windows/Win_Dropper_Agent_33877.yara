rule Win_Dropper_Agent_33877
{
strings:
	$a0 = { 4d5a80000100000004001000ff }
	$a1 = { 00be00004d5a80000100000004001000ffff0000400100000000000040 }

condition:
	$a0 and $a1
}

        
