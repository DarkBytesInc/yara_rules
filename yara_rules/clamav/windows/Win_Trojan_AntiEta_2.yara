rule Win_Trojan_AntiEta_2
{
strings:
	$a0 = { b80043cc72??890e????b8014333c9cc72??b8023dcc73??b801438b0e????cceb }

condition:
	$a0
}

        
