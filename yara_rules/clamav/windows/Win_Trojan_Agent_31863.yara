rule Win_Trojan_Agent_31863
{
strings:
	$a0 = { 63744e6574776f726b210000558becb9050000006a006a004975f953565733c05568 }

condition:
	$a0
}

        
