rule Win_Spyware_Small_2058
{
strings:
	$a0 = { 8d45e8895df0508d45f05053683f000f0053535368f41240006802000080ff1508104000 }

condition:
	$a0
}

        
