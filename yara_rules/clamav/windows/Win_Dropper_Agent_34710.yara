rule Win_Dropper_Agent_34710
{
strings:
	$a0 = { 565733fe5f535783c40490f7d668990903578b342483c40453bb4658302c81eb002d3db9011c245b }

condition:
	$a0
}

        
