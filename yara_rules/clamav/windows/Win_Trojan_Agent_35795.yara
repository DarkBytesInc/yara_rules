rule Win_Trojan_Agent_35795
{
strings:
	$a0 = { e8010000009090e801000000016800204000ff15ac104000e810000000566972 }

condition:
	$a0
}

        
