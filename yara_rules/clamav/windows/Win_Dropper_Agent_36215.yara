rule Win_Dropper_Agent_36215
{
strings:
	$a0 = { 60be00506c008dbe00c0d3ff5789e58d9c2480c1ffff31c05039dc75fb4646536862982c005783c30453684263000056 }

condition:
	$a0
}

        
