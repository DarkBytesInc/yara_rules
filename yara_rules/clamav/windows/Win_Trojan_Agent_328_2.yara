rule Win_Trojan_Agent_328_2
{
strings:
	$a0 = { 8d45e8895dec508d45ec5053683f000f0053535368c41240006802000080ff1508104000 }

condition:
	$a0
}

        
