rule Win_Worm_Pinit_5
{
strings:
	$a0 = { 347b66beea5ac745e72e646c6cf7d3beda7ee48db9e15b156bf7d3c645eb00c1 }

condition:
	$a0
}

        
