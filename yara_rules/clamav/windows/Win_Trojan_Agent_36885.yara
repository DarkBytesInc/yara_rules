rule Win_Trojan_Agent_36885
{
strings:
	$a0 = { c78528fcffff080000008b55c88995dcfbffffc745c80000000068e82e42008b95dcfbffff8d4dd0ff153013400050ff1588104000898540fcffffc78538fcffff08000000 }

condition:
	$a0
}

        
