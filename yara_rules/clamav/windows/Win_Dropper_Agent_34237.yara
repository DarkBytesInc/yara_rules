rule Win_Dropper_Agent_34237
{
strings:
	$a0 = { bf001040008d6f21ff554483c709ff554483c707ff554483c708ff5544bb00144000c6830004000000be }

condition:
	$a0
}

        
