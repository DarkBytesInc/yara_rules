rule Win_Dropper_Agent_34534
{
strings:
	$a0 = { f520005368656c6c4578656375746541004f204441204e494745525348454c }

condition:
	$a0
}

        
