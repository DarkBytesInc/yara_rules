rule Win_Trojan_Agent_35057
{
strings:
	$a0 = { 686880400050ff15b87040008bf056ff15c070400085c0740433c05ec3ff156470400050ffd65ec3 }

condition:
	$a0
}

        
