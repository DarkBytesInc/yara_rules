rule Win_Worm_N_81
{
strings:
	$a0 = { 6b96bd8e72a98bacd42d3de8bd82177cfb6e696c8ca1730c11c4e3234977161dbd46fe490c381bd0a0796571215a1114f68aa7836720576f709c92d3a40a7f46 }

condition:
	$a0
}

        
