rule Win_Dropper_Agent_36073
{
strings:
	$a0 = { 6878114000e8eeffffff000000000000300000003800000000000000a1416daeb4e44f409da31e42224c }

condition:
	$a0
}

        
