rule Win_Dropper_Agent_34234
{
strings:
	$a0 = { 5c6e73457865632e646c6c0022fd99805c756e7261722e657865222065202d6f2b202d70 }

condition:
	$a0
}

        
